using System.Text;
using System.Text.Encodings.Web;
using IdServer.STS.Identity.Helpers;
using IdsTemp.Helpers;
using IdsTemp.Models;
using IdsTemp.Models.Manage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;

namespace IdsTemp.MainModule.Controllers;

[Authorize]
public class ManageController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    private readonly SignInManager<ApplicationUser> _signInManager;

    // private readonly IEmailSender _emailSender;
    private readonly ILogger<ManageController> _logger;
    private readonly UrlEncoder _urlEncoder;
    private readonly IEmailSender _emailSender;

    private const string RecoveryCodesKey = nameof(RecoveryCodesKey);
    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    [TempData] public string StatusMessage { get; set; }

    public ManageController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IEmailSender emailSender,
        ILogger<ManageController> logger,
        UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailSender = emailSender;
        _logger = logger;
        _urlEncoder = urlEncoder;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);

        if (user == null)
            return NotFound("User Not Found");

        var model = await BuildManageIndexViewModelAsync(user);

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(ProfileViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound("User is not found");

        var email = user.Email;
        if (model.Email != email)
        {
            var setEmailResult = await _userManager.SetEmailAsync(user, model.Email);
            if (!setEmailResult.Succeeded)
                throw new ApplicationException("Error setting email");
        }

        var phoneNumber = user.PhoneNumber;
        if (model.PhoneNumber != phoneNumber)
        {
            var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, model.PhoneNumber);
            if (!setPhoneResult.Succeeded)
                throw new ApplicationException("Error setting phone");
        }

        await UpdateUserClaimsAsync(model, user);

        StatusMessage = "Profile updated!";

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendVerificationEmail(ProfileViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound("User not found");

        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code },
            HttpContext.Request.Scheme);

        await _emailSender.SendEmailAsync(model.Email, "Confirm your email",
            $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

        StatusMessage = "Verification sent";

        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> ChangePassword()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound("User is not found");

        var hasPassword = await _userManager.HasPasswordAsync(user);
        if (!hasPassword)
            return RedirectToAction(nameof(SetPassword));

        var model = new ChangePasswordViewModel { StatusMessage = StatusMessage };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound("User is not found");

        var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        if (!changePasswordResult.Succeeded)
        {
            AddErrors(changePasswordResult);
            return View(model);
        }

        await _signInManager.RefreshSignInAsync(user);
        _logger.LogInformation("PasswordChangedLog | {UserName}", user.UserName);

        StatusMessage = "Password changed";

        return RedirectToAction(nameof(ChangePassword));
    }

    [HttpGet]
    public async Task<IActionResult> SetPassword()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound("User is not found");

        var hasPassword = await _userManager.HasPasswordAsync(user);

        if (hasPassword)
            return RedirectToAction(nameof(ChangePassword));

        var model = new SetPasswordViewModel { StatusMessage = StatusMessage };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound("User is not found");

        var addPasswordResult = await _userManager.AddPasswordAsync(user, model.NewPassword);
        if (!addPasswordResult.Succeeded)
        {
            AddErrors(addPasswordResult);
            return View(model);
        }

        await _signInManager.RefreshSignInAsync(user);
        StatusMessage = "Password set";

        return RedirectToAction(nameof(SetPassword));
    }

    [HttpGet]
    public async Task<IActionResult> PersonalData()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DownloadPersonalData()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        _logger.LogInformation("User with ID '{UserId}' asked for their personal data", _userManager.GetUserId(User));

        // Only include personal data for download
        var personalDataProps = typeof(ApplicationUser).GetProperties().Where(
            prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
        var personalData = personalDataProps.ToDictionary(p => p.Name, p => p.GetValue(user)?.ToString() ?? "null");

        var logins = await _userManager.GetLoginsAsync(user);
        foreach (var l in logins)
        {
            personalData.Add($"{l.LoginProvider} external login provider key", l.ProviderKey);
        }

        personalData.Add($"Authenticator Key", await _userManager.GetAuthenticatorKeyAsync(user));

        Response.Headers.Add("Content-Disposition", "attachment; filename=PersonalData.json");
        return new FileContentResult(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(personalData)), "text/json");
    }

    [HttpGet]
    public async Task<IActionResult> DeletePersonalData()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        var deletePersonalDataViewModel = new DeletePersonalDataViewModel
        {
            RequirePassword = await _userManager.HasPasswordAsync(user)
        };

        return View(deletePersonalDataViewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeletePersonalData(DeletePersonalDataViewModel deletePersonalDataViewModel)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        deletePersonalDataViewModel.RequirePassword = await _userManager.HasPasswordAsync(user);
        if (deletePersonalDataViewModel.RequirePassword)
        {
            if (!await _userManager.CheckPasswordAsync(user, deletePersonalDataViewModel.Password))
            {
                ModelState.AddModelError(string.Empty, "Password is not correct");
                return View(deletePersonalDataViewModel);
            }
        }

        var result = await _userManager.DeleteAsync(user);
        var userId = await _userManager.GetUserIdAsync(user);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"Unexpected error occurred deleting user | userId: {user.Id}");
        }

        await _signInManager.SignOutAsync();

        _logger.LogInformation("User with ID '{UserId}' deleted themselves", userId);

        return Redirect("~/");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> GenerateRecoveryCodes()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        if (!user.TwoFactorEnabled)
        {
            AddError("Cannot generate recovery codes for user as they do not have 2FA enabled.");
            return View();
        }

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
        
        var userId = await _userManager.GetUserIdAsync(user);
        _logger.LogInformation("User with ID '{UserId}' has generated new 2FA recovery codes", userId);
        StatusMessage = "You have generated new recovery codes.";

        var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };

        return View(nameof(ShowRecoveryCodes), model);
    }

    [HttpGet]
    public IActionResult ShowRecoveryCodes()
    {
        var recoveryCodes = (string[])TempData[RecoveryCodesKey];
        if (recoveryCodes == null)
        {
            return RedirectToAction(nameof(TwoFactorAuthentication));
        }

        var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes };

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> TwoFactorAuthentication()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        var model = new TwoFactorAuthenticationViewModel
        {
            HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null,
            Is2FaEnabled = user.TwoFactorEnabled,
            RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user),
            IsMachineRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user)
        };

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> ForgetTwoFactorClient()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        await _signInManager.ForgetTwoFactorClientAsync();

        StatusMessage =
            "The current browser has been forgotten. When you login again from this browser you will be prompted for your 2fa code";

        return RedirectToAction(nameof(TwoFactorAuthentication));
    }

    [HttpGet]
    public async Task<IActionResult> Disable2FaWarning()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        if (!user.TwoFactorEnabled)
            throw new InvalidOperationException($"Cannot disable 2FA for user as it's not currently enabled.");

        return View(nameof(Disable2Fa));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Disable2Fa()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        var disable2FaResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
        if (!disable2FaResult.Succeeded)
            throw new InvalidOperationException($"Unexpected error occurred disabling 2FA.");

        _logger.LogInformation("User with ID '{UserId}' has disabled 2fa", _userManager.GetUserId(User));
        StatusMessage = "2fa has been disabled. You can reenable 2fa when you setup an authenticator app";

        return RedirectToAction(nameof(TwoFactorAuthentication));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);
        var userId = await _userManager.GetUserIdAsync(user);

        _logger.LogInformation("User with ID '{UserId}' has reset their authentication app key", userId);

        await _signInManager.RefreshSignInAsync(user);
        ViewData["StatusMessage"] = "Your authenticator app key has been reset, you will need to configure your authenticator app using the new key.";

        return RedirectToAction(nameof(EnableAuthenticator));
    }

    [HttpGet]
    public IActionResult ResetAuthenticatorWarning()
    {
        return View(nameof(ResetAuthenticator));
    }

    [HttpGet]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        var model = new EnableAuthenticatorViewModel();
        await LoadSharedKeyAndQrCodeUriAsync(user, model);

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorViewModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        if (!ModelState.IsValid)
        {
            await LoadSharedKeyAndQrCodeUriAsync(user, model);
            return View(model);
        }

        var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var is2FaTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2FaTokenValid)
        {
            ModelState.AddModelError("ErrorCode", "Verification code is invalid");
            await LoadSharedKeyAndQrCodeUriAsync(user, model);
            return View(model);
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        var userId = await _userManager.GetUserIdAsync(user);

        _logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app", userId);

        StatusMessage = "Your authenticator app has been verified.";

        if (await _userManager.CountRecoveryCodesAsync(user) == 0)
        {
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            TempData[RecoveryCodesKey] = recoveryCodes.ToArray();

            return RedirectToAction(nameof(ShowRecoveryCodes));
        }

        return RedirectToAction(nameof(TwoFactorAuthentication));
    }

    [HttpGet]
    public async Task<IActionResult> GenerateRecoveryCodesWarning()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
            return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

        if (!user.TwoFactorEnabled)
            throw new InvalidOperationException(
                $"Cannot generate recovery codes for user because they do not have 2FA enabled.");

        return View(nameof(GenerateRecoveryCodes));
    }


    /*Helpers for Manage*/
    private async Task<ProfileViewModel> BuildManageIndexViewModelAsync(ApplicationUser user)
    {
        var claims = await _userManager.GetClaimsAsync(user);
        var profile = OpenIdClaimHelpers.ExtractProfileInfo(claims);

        var model = new ProfileViewModel()
        {
            UserName = user.UserName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            IsEmailConfirmed = user.EmailConfirmed,
            StatusMessage = StatusMessage,
            Name = profile.FullName,
            Website = profile.Website,
            Profile = profile.Profile,
            Country = profile.Country,
            Region = profile.Region,
            PostalCode = profile.PostalCode,
            Locality = profile.Locality,
            StreetAddress = profile.StreetAddress
        };
        return model;
    }

    private async Task UpdateUserClaimsAsync(ProfileViewModel model, ApplicationUser user)
    {
        var claims = await _userManager.GetClaimsAsync(user);
        var oldProfile = OpenIdClaimHelpers.ExtractProfileInfo(claims);
        var newProfile = new OpenIdProfile
        {
            Website = model.Website,
            StreetAddress = model.StreetAddress,
            Locality = model.Locality,
            PostalCode = model.PostalCode,
            Region = model.Region,
            Country = model.Country,
            FullName = model.Name,
            Profile = model.Profile
        };

        var claimsToRemove = OpenIdClaimHelpers.ExtractClaimsToRemove(oldProfile, newProfile);
        var claimsToAdd = OpenIdClaimHelpers.ExtractClaimsToAdd(oldProfile, newProfile);
        var claimsToReplace = OpenIdClaimHelpers.ExtractClaimsToReplace(claims, newProfile);

        await _userManager.RemoveClaimsAsync(user, claimsToRemove);
        await _userManager.AddClaimsAsync(user, claimsToAdd);

        foreach (var pair in claimsToReplace)
        {
            await _userManager.ReplaceClaimAsync(user, pair.Item1, pair.Item2);
        }
    }

    private async Task LoadSharedKeyAndQrCodeUriAsync(ApplicationUser user, EnableAuthenticatorViewModel model)
    {
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        model.SharedKey = FormatKey(unformattedKey);
        model.AuthenticatorUri = GenerateQrCodeUri(user.Email, unformattedKey);
    }

    private string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        var currentPosition = 0;

        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
            currentPosition += 4;
        }

        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string unformattedKey)
    {
        return string.Format(
            AuthenticatorUriFormat,
            _urlEncoder.Encode("IdServer.STS.Identity"),
            _urlEncoder.Encode(email),
            unformattedKey);
    }

    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }

    private void AddError(string description, string title = "")
    {
        ModelState.AddModelError(title, description);
    }
}