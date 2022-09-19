using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.MainModule.Admin;

[SecurityHeaders]
[Authorize]
public class AdminController : Controller
{
    // GET
    public IActionResult Index()
    {
        return View();
    }
}