using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;
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
    private readonly ILogger<UsersController> _logger;

    public UsersController(
        IUserRepository userRepository,
        IRoleRepository roleRepository, 
        ILogger<UsersController> logger)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _logger = logger;
    }

    public async Task<IActionResult> Index(string sortExpression="", string searchText = "", int pg = 1, int pageSize = 5)
    {
        var sortModel = new SortModel();
        sortModel.AddColumn("username");
        sortModel.AddColumn("email");
        sortModel.AddColumn("role");
        sortModel.ApplySort(sortExpression);
        ViewData["sortModel"] = sortModel;
        
        ViewBag.SearchText = searchText;
        
        var users = await _userRepository.GetAllUserAsync(sortModel.SortedProperty, sortModel.SortedOrder, searchText, pg, pageSize);

        var paginator = new PaginatorModel(users.TotalRecords, pg, pageSize);
        paginator.SearchText = searchText;
        paginator.SortExpression = sortExpression;
        ViewBag.Paginator = paginator;
        
        
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
            _logger.LogInformation("Create user is success!");
            await _userRepository.CreateUserAsync(createUser);
            return RedirectToAction("Index");
        }

        catch (Exception e)
        {
            _logger.LogError("Create new user is failed", e);
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
    
    private SortModel ApplySort(string sortExpression)
    {
        ViewData["SortParamUsername"] = "username";
        ViewData["SortParamEmail"] = "email";
        ViewData["SortParamRole"] = "role";
        ViewData["SortIconUsername"] = "";
        ViewData["SortIconEmail"] = "";
        ViewData["SortIconRole"] = "";

        var sortModel = new SortModel();

        switch (sortExpression.ToLower())
        {
            case "username_desc":
                sortModel.SortedOrder = SortOrder.Descending;
                sortModel.SortedProperty = "username";
                ViewData["SortIconUsername"] = "bi bi-arrow-up";
                ViewData["SortParamUsername"] = "username";
                break;
            case "email":
                sortModel.SortedOrder = SortOrder.Ascending;
                sortModel.SortedProperty = "email";
                ViewData["SortIconEmail"] = "bi bi-arrow-down";
                ViewData["SortParamEmail"] = "email_desc";
                break;
            case "email_desc":
                sortModel.SortedOrder = SortOrder.Descending;
                sortModel.SortedProperty = "email";
                ViewData["SortIconEmail"] = "bi bi-arrow-up";
                ViewData["SortParamEmail"] = "email";
                break;
            case "role":
                sortModel.SortedOrder = SortOrder.Ascending;
                sortModel.SortedProperty = "role";
                ViewData["SortIconRole"] = "bi bi-arrow-down";
                ViewData["SortParamRole"] = "role_desc";
                break;
            case "role_desc":
                sortModel.SortedOrder = SortOrder.Descending;
                sortModel.SortedProperty = "role";
                ViewData["SortIconRole"] = "bi bi-arrow-up";
                ViewData["SortParamRole"] = "role";
                break;
            default:
                sortModel.SortedOrder = SortOrder.Ascending;
                sortModel.SortedProperty = "username";
                ViewData["SortIconUsername"] = "bi bi-arrow-down";
                ViewData["SortParamUsername"] = "username_desc";
                break;
        }

        return sortModel;
    }
}