using IdentityModel;
using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

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




}