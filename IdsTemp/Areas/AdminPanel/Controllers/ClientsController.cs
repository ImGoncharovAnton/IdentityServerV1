using IdentityModel;
using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

[Authorize(Roles = "ISAdministrator")]
[Area("AdminPanel")]
public class ClientsController : Controller
{
    private readonly IClientRepository _clientRepository;

    public ClientsController(IClientRepository clientRepository)
    {
        _clientRepository = clientRepository;
    }

    // GET
    public async Task<IActionResult> Index(string filter)
    {
        var clients = await _clientRepository.GetAllAsync(filter);
        var ClientsVm = new ClientViewModel
        {
            Clients = clients
        };

        return View(ClientsVm);
    }

    //EDIT
    public async Task<IActionResult> Edit(string id)
    {
        var model = await _clientRepository.GetByIdAsync(id);

        if (model == null)
        {
            return RedirectToAction("Index");
        }

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(ClientModel model)
    {
        if (ModelState.IsValid)
        {
            await _clientRepository.UpdateAsync(model);
            return RedirectToAction("Index");
        }

        return View(model);
    }

    // NEW
    public IActionResult New()
    {
        var model = new CreateClientModel 
        {
            Secret = Convert.ToBase64String(CryptoRandom.CreateRandomKey(16))
        };
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> New(CreateClientModel model)
    {
        if (ModelState.IsValid)
        {
            await _clientRepository.CreateAsync(model);

            return RedirectToAction("Index", new { id = model.Name });
        }

        return View(model);
    }

    // DELETE

    public async Task<IActionResult> Delete(string? id)
    {
        if (id == null)
            return NotFound();

        try
        {
            var client = await _clientRepository.GetByIdAsync(id);
            return View(client);
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
        await _clientRepository.DeleteAsync(id);
        return RedirectToAction(nameof(Index));
    }
}
