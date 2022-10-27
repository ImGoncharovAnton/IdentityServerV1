using System.Text.Encodings.Web;
using IdServer.STS.Identity.Helpers;
using IdsTemp.Helpers;
using IdsTemp.Models;
using IdsTemp.Models.Manage;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.MainModule.Controllers;

[Authorize]
public class ManageController : Controller
{
    
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<ManageController> _logger;
    private readonly UrlEncoder _urlEncoder;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
    
    [TempData]
    public string StatusMessage { get; set; }
    
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
        {
            return NotFound("User Not Found");
        }
        
        var model = await 
        
        
        return View();
    }
    
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
}