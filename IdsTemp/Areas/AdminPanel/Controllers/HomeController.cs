using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
public class HomeController : Controller
{
    // GET
    public IActionResult Index()
    {
        return View();
    }
}