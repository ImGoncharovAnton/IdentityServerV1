using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Authorize(Roles = "ISAdministrator")]
[Area("AdminPanel")]
public class RolesController : Controller
{
    private readonly IRoleRepository _roleRepository;

    public RolesController(IRoleRepository roleRepository)
    {
        _roleRepository = roleRepository;
    }


    public async Task<IActionResult> Index(string filter)
    {
        var roles = await _roleRepository.GetRolesAsync(filter);
        var rolesVm = new RolesViewModel
        {
            Roles = roles
        };
        
        return View(rolesVm);
    }

    public ActionResult New()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> New(RoleModel model)
    {
        if (!ModelState.IsValid) return View(model);

        try
        {
            await _roleRepository.CreateRoleAsync(model.Name);
            return RedirectToAction("Index");
        }
        // Добавить обработку и вывод ошибок
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        
    }

    public async Task<ActionResult> Edit(string? id)
    {
        if (id == null)
        {
            return NotFound();
        }

        var role = await _roleRepository.GetRoleAsync(id);
        if (role != null)
        {
            return View(role);
        }
        else
        {
            return NotFound();
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(string id, RoleModel model)
    {
        if (id != model.Id)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            await _roleRepository.UpdateRoleAsync(id, model);
            return RedirectToAction(nameof(Index));
        }

        return View(model);
    }
    
    public async Task<ActionResult> Delete(string? id)
    {
        if (id != null)
        {
            await _roleRepository.DeleteRole(id);
            return RedirectToAction(nameof(Index));
        }
        return RedirectToAction(nameof(Index));
    }
    
   
}