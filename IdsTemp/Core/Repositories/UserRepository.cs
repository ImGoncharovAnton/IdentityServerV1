using System.Security.Claims;
using IdentityModel;
using IdsTemp.Core.IRepositories;
using IdsTemp.Data;
using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Core.Repositories;

public class UserRepository : IUserRepository
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly ApplicationDbContext _context;

    public UserRepository(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager, 
        ApplicationDbContext context)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
    }

    public async Task<IEnumerable<UserModel>> GetAllUserAsync(string filter = null)
    {
        var query = _userManager.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter))
        {
            query = query.Where(x =>
                x.FirstName.Contains(filter) | x.LastName.Contains(filter) | x.UserName.Contains(filter) |
                x.Email.Contains(filter));
        }

        var result = query.Select(user => new UserModel
        {
            Id = user.Id,
            UserName = user.UserName,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            Phone = user.PhoneNumber,
            Role = user.UserRoles.Select(ur => ur.Role.Name).FirstOrDefault()
        });

        return await result.AsTracking().ToListAsync();
    }

    public async Task<UserModel> GetUserAsync(string id)
    {
        var findUser = await _context.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .FirstOrDefaultAsync(x => x.Id == id);
        if (findUser == null)
            throw new Exception($"The user with id = {id} is not found");

        var result = new UserModel
        {
            Id = findUser.Id,
            UserName = findUser.UserName,
            FirstName = findUser.FirstName,
            LastName = findUser.LastName,
            Email = findUser.Email,
            Phone = findUser.PhoneNumber,
            Role = findUser.UserRoles.Select(ur => ur.Role.Name).FirstOrDefault()
        };

        return result;
    }

    public async Task<IdentityResult> CreateUserAsync(UserCreateModel createModel)
    {
        var newUser = new ApplicationUser
        {
            UserName = createModel.UserName,
            Email = createModel.Email,
            FirstName = createModel.FirstName,
            LastName = createModel.LastName,
            PhoneNumber = createModel.Phone
        };

        var result = await _userManager.CreateAsync(newUser, createModel.Password);
        if (result.Succeeded)
        {
            var findRole = await _roleManager.FindByIdAsync(createModel.SelectedRoleId);
            if (findRole != null)
            {
                await _userManager.AddToRoleAsync(newUser, findRole.Name);
                /*await _userManager.AddClaimsAsync(newUser, new Claim[]
                {
                    new Claim(JwtClaimTypes.Role, findRole.Name)
                });*/
                return result;
            }
        } 
        throw new Exception($"The User {createModel.UserName} has not been added");
    }

    public async Task<IdentityResult> EditUserAsync(string id, UserEditModel model)
    {
        var findUser = await _context.Users
            .Include(x => x.UserRoles)
            .ThenInclude(x => x.Role)
            .FirstOrDefaultAsync(x => x.Id == id);
        if (findUser == null)
            throw new Exception($"The user with {id} not found");

        var userClaims = await _userManager.GetClaimsAsync(findUser);

        findUser.UserName = model.UserName;
        findUser.FirstName = model.FirstName;
        findUser.LastName = model.LastName;
        findUser.Email = model.Email;
        findUser.PhoneNumber = model.Phone;

        var queryRoles = _context.UserRoles.AsQueryable();
        var userRoles = queryRoles.Where(x => x.UserId == findUser.Id);
        if (userRoles.Any())
        {

            var listRoles = userRoles.Select(x => x.Role.Name).ToList();

            await _userManager.RemoveFromRolesAsync(findUser, listRoles);
            
        }


        var findRole = await _roleManager.FindByIdAsync(model.SelectedRoleId);
        if (findRole != null)
            await _userManager.AddToRoleAsync(findUser, findRole.Name);


        await _userManager.RemoveClaimsAsync(findUser, userClaims);
        /*await _userManager.AddClaimsAsync(findUser, new Claim[]
        {
            new Claim(JwtClaimTypes.Role, findRole.Name)
        });*/

        var userResult = await _userManager.UpdateAsync(findUser);
        if (userResult.Succeeded)
        {
            return userResult;
        }
        else
        {
            throw new Exception("User has not been created");
        }
    }

    public async Task<bool> DeleteUser(string id)
    {
        var findUser = await _userManager.FindByIdAsync(id);
        if (findUser != null)
        {
            await _userManager.DeleteAsync(findUser);
            return true;
        }

        return false;
    }
}