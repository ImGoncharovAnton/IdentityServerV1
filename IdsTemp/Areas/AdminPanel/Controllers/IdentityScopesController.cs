using IdentityModel;
using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Authorize(Roles = "ISAdministrator")]
[Area("AdminPanel")]
public class IdentityScopesController : Controller
{
    private readonly IIdentityScopeRepository _identityScopeRepository;

    public IdentityScopesController(IIdentityScopeRepository identityScopeRepository)
    {
        _identityScopeRepository = identityScopeRepository;
    }

    // GET
    public async Task<IActionResult> Index(string filter)
    {
        var scopes = await _identityScopeRepository.GetAllAsync(filter);
        var ScopesVm = new IdentityScopeViewModel
        {
            Scopes = scopes
        };

        return View(ScopesVm);
    }

    //EDIT
    public async Task<IActionResult> Edit(string id)
    {
        var model = await _identityScopeRepository.GetByIdAsync(id);
        if (model == null)
        {
            return RedirectToAction("Index");
        }

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(IdentityScopeModel model, string button)
    {
        if (button == "delete")
        {
            await _identityScopeRepository.DeleteAsync(model.Name);
            return RedirectToAction("Index");
        }

        if (ModelState.IsValid)
        {
            await _identityScopeRepository.UpdateAsync(model);
            return RedirectToAction("Index");
        }

        return View();
    }

    // NEW
    public IActionResult New()
    {
        var model = new IdentityScopeModel();
       
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> New(IdentityScopeModel model)
    {
        if (ModelState.IsValid)
        {
            await _identityScopeRepository.CreateAsync(model);

            return RedirectToAction("Index");
        }

        return View();
    }

    // DELETE

    public async Task<IActionResult> Delete(string? id)
    {
        if (id == null)
            return NotFound();

        try
        {
            var identity = await _identityScopeRepository.GetByIdAsync(id);
            return View(identity);
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
        await _identityScopeRepository.DeleteAsync(id);
        return RedirectToAction(nameof(Index));
    }
}