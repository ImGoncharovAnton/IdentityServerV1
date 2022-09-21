using IdsTemp.Core.IRepositories;
using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Core.Repositories;

public class UserRepository: IUserRepository
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public UserRepository(
        UserManager<ApplicationUser> userManager, 
        RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public async Task<IEnumerable<UserModel>> GetAllUserAsync(string filter = null)
    {

        var query = _userManager.Users.AsQueryable();
        
        if (!string.IsNullOrWhiteSpace(filter))
        {
            query = query.Where(x => x.FirstName.Contains(filter) | x.LastName.Contains(filter) | x.UserName.Contains(filter) | x.Email.Contains(filter));
        }

        var result = query.Select(user => new UserModel
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            Phone = user.PhoneNumber,
            Role = user.UserRoles.Select(ur => ur.Role.Name).FirstOrDefault()
        });
        
        return await result.AsTracking().ToListAsync();
    }
}