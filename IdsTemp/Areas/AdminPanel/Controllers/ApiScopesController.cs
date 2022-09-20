using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Mvc;

namespace IdsTemp.Areas.AdminPanel.Controllers;

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

    public IActionResult Edit()
    {
        return View();
    }

    public IActionResult New()
    {
        return View();
    }
}