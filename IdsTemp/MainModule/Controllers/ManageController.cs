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

namespace IdsTemp.MainModule.Controllers;

[Authorize]
public class ManageController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    // private readonly IEmailSender _emailSender;
    private readonly ILogger<ManageController> _logger;
    private readonly UrlEncoder _urlEncoder;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    [TempData] public string StatusMessage { get; set; }

    public ManageController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        // IEmailSender emailSender,
        ILogger<ManageController> logger,
        UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        // _emailSender = emailSender;
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

        /*await _emailSender.SendEmailAsync(model.Email, "Confirm email",
            $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");*/

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