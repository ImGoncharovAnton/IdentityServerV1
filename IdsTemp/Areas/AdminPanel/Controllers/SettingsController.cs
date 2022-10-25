using Duende.IdentityServer.Extensions;
using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Authorize(Roles = "ISAdministrator")]
[Area("AdminPanel")]
public class SettingsController : Controller
{
    /*private readonly IHttpContextAccessor _httpContextAccessor;*/

    /*public SettingsController(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }*/

    public IActionResult Index()
    {
        // var cookies = _httpContextAccessor.HttpContext.Request.Cookies;
        // var isTrueThemeName = cookies.ContainsKey("currentTheme");

        var isTrueThemeName = Request.Cookies.ContainsKey("currentTheme");

        var settingsViewModel = new SettingsViewModel
        {
            ThemesList = GetSelectedListItems()
        };

        if (isTrueThemeName)
        {
            var cookieThemeName = Request.Cookies["currentTheme"];
            settingsViewModel.SelectedThemeId = cookieThemeName;
        }

        return View(settingsViewModel);
    }

    [HttpPost]
    public IActionResult Index(SettingsViewModel model)
    {
        var cookies = new CookieOptions
        {
            Expires = DateTime.UtcNow.AddYears(1)
        };

        Response.Cookies.Append("currentTheme", model.SelectedThemeId, cookies);
        
        return RedirectToAction(nameof(Index));
    }

    private static List<SelectListItem> GetSelectedListItems()
    {
        var themesList = new List<ThemeDetails>
        {
            new ThemeDetails { Id = "default", Value = "Default" },
            new ThemeDetails { Id = "green", Value = "Green" },
            new ThemeDetails { Id = "red", Value = "Red" },
            new ThemeDetails { Id = "blue", Value = "Blue" }
        };

        var selectListItem = themesList.Select(x => new SelectListItem
        {
            Value = x.Id.ToString(),
            Text = x.Value
        }).ToList();

        return selectListItem;
    }
}