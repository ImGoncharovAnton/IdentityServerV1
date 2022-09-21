using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Area("AdminPanel")]
public class UsersController : Controller
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;

    public UsersController(
        IUserRepository userRepository, 
        IRoleRepository roleRepository)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
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
    
    public async Task<IActionResult> New()
    {
        var roles = await _roleRepository.GetRolesAsync();
        
        var selectListItem = roles.Select(x => new SelectListItem
        {
            Value = x.Id.ToString(),
            Text = x.Name
        }).ToList();
        
        var createUserVm = new UserCreateModel
        {
            RolesList = selectListItem
        };
        
        return View(createUserVm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> New(UserCreateModel createUser)
    {
        if (!ModelState.IsValid) return View(createUser);

        try
        {
            await _userRepository.CreateUserAsync(createUser);
            return RedirectToAction("Index");
        }
        // Добавить обработку и вывод ошибок
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task<IActionResult> Edit(string? id)
    {
        if (id == null)
            return NotFound();
        try
        {
            // var user = await _roleRepository
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return NotFound();
        }
       
        
        return View();
    }
    
    public IActionResult Delete()
    {
        return View();
    }
}