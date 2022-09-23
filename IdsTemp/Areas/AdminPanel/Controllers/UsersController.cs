using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Authorize(Roles = "ISAdministrator")]
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

        catch (Exception e)
        {
            Console.WriteLine(e);
            return NotFound();
        }
    }

    public async Task<IActionResult> Edit(string? id)
    {
        if (id == null)
            return NotFound();
        try
        {
            var user = await _userRepository.GetUserAsync(id);
            var userRoleId = await _roleRepository.GetRoleIdByName(user.Role);
            var roles = await _roleRepository.GetRolesAsync();

            var selectListItem = roles.Select(x => new SelectListItem
            {
                Value = x.Id.ToString(),
                Text = x.Name
            }).ToList();

            var editUserVm = new UserEditModel
            {
                Id = user.Id,
                UserName = user.UserName,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Phone = user.Phone,
                RolesList = selectListItem,
                SelectedRoleId = userRoleId
            };
            return View(editUserVm);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw new Exception("Exception", e);
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(string id, UserEditModel model)
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            await _userRepository.EditUserAsync(id, model);
            return RedirectToAction(nameof(Index));
        }

        return View(model);
    }

    public async Task<IActionResult> Delete(string? id)
    {
        if (id == null)
            return NotFound();

        try
        {
            var user = await _userRepository.GetUserAsync(id);
            return View(user);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return NotFound();
        }
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(string id)
    {
        await _userRepository.DeleteUser(id);
        return RedirectToAction(nameof(Index));
    }
}