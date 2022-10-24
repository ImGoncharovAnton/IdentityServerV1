using Duende.IdentityServer.Extensions;
using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Authorization;
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
        var isTrueThemeName = Request.Cookies.ContainsKey("currentTheme");
        
        // var cookies = _httpContextAccessor.HttpContext.Request.Cookies;
        // var isTrueThemeName = cookies.ContainsKey("currentTheme");
        

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

        var settingsViewModel = new SettingsViewModel
        {
            ThemesList = selectListItem
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
        if (ModelState.IsValid)
        {
            var cookies = new CookieOptions
            {
                Expires = DateTime.UtcNow.AddMonths(1)
            };

            Response.Cookies.Append("theme", model.SelectedThemeId, cookies);
            return View(model);
        }
        return View(model);
    }
    
    
    // // POST
    // public IActionResult SetTheme(string data)
    // {
    //     CookieOptions cookies = new CookieOptions();
    //     cookies.Expires = DateTime.Now.AddDays(7);
    //     
    //     Response.Cookies.Append("theme", data, cookies);
    //     return Ok();
    // }
    public static void SelectListItem()
    {
        
    }
}