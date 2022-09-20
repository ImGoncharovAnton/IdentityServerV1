using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
public class UsersController : Controller
{
    private readonly IUserRepository _userRepository;

    public UsersController(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    public async Task<IActionResult> Index(string filter)
    {
        var users = await _userRepository.GetAllUserAsync(filter);
        var usersVm = new UsersViewModel
        {
            Users = users
        };
        return View(usersVm);
    }
    
    public IActionResult New()
    {
        return View();
    }
    
    public IActionResult Edit()
    {
        return View();
    }
    
    public IActionResult Delete()
    {
        return View();
    }
}