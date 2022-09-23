using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Authorize(Roles = "ISAdministrator")]
[Area("AdminPanel")]
public class ApiScopesController : Controller
{
    private readonly IApiScopeRepository _apiScopeRepository;

    public ApiScopesController(IApiScopeRepository apiScopeRepository)
    {
        _apiScopeRepository = apiScopeRepository;
    }
    
    // GET
    public async Task<IActionResult> Index(string filter)
    {
        
        var apiScopes = await _apiScopeRepository.GetAllAsync(filter);
        var apiScopesVm = new ApiScopeViewModel
        {
            ApiScopes = apiScopes
        };
        
        return View(apiScopesVm);
    }

    // EDIT
    public async Task<IActionResult> Edit(string id)
    {
        var InputModel = await _apiScopeRepository.GetByIdAsync(id);

        if (InputModel == null)
        {
            return RedirectToAction("Index");
        }
        return View(InputModel);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(ApiScopeModel model, string button)
    {
        if (button == "delete")
        {
            await _apiScopeRepository.DeleteAsync(model.Name);
            return RedirectToAction("Index");
        }

        if (ModelState.IsValid)
        {
            await _apiScopeRepository.UpdateAsync(model);
            return RedirectToAction("Index");
        }

        return View();
    }

    // NEW
    public IActionResult New()
    {
        var inputModel = new ApiScopeModel();
        return View(inputModel);
    }

    [HttpPost]
    public async Task<IActionResult> New(ApiScopeModel model )
    {
        if (ModelState.IsValid)
        {
            await _apiScopeRepository.CreateAsync(model);

            return RedirectToAction("Index", new { id = model.Name });
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
            var scope = await _apiScopeRepository.GetByIdAsync(id);
            return View(scope);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return NotFound();
        }
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteConfirmed(string name)
    {
        await _apiScopeRepository.DeleteAsync(name);
        return RedirectToAction(nameof(Index));
    }

}