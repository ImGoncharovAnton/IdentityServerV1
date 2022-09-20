using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
public class ClientsController : Controller
{
    // GET
    public IActionResult Index()
    {
        return View();
    }
}