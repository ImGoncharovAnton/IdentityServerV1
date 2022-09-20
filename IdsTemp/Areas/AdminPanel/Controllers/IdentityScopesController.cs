using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
public class IdentityScopesController : Controller
{
    // GET
    public IActionResult Index()
    {
        return View();
    }
}