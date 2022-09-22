using IdsTemp.Core.IRepositories;
using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Core.Repositories;

public class RoleRepository: IRoleRepository
{
    private readonly RoleManager<ApplicationRole> _roleManager;

    public RoleRepository(
        RoleManager<ApplicationRole> roleManager, 
        UserManager<ApplicationUser> userManager)
    {
        _roleManager = roleManager;
    }


    public async Task<ICollection<RoleModel>> GetRolesAsync(string filter = null)
    {
        var query = _roleManager.Roles.AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter))
        {
            query = query.Where(x => x.Name.Contains(filter));
        }

        var result = query.Select(x => new RoleModel
        {
            Id = x.Id,
            Name = x.Name
        });
        
        return await result.AsNoTracking().ToListAsync();
    }

    public async Task<RoleModel> GetRoleAsync(string id)
    {
        var role = await _roleManager.FindByIdAsync(id);
        if (role != null)
        {
            return new RoleModel
            {
                Id = role.Id,
                Name = role.Name
            };
        }
        else
        {
            throw new Exception("The role has not found");
        }
    }

    public async Task<string> GetRoleIdByName(string roleName)
    {
        var role = await _roleManager.FindByNameAsync(roleName);
        if (role != null)
        {
            return role.Id;
        }
        else
        {
           throw new Exception("Role has not found");
        }
    }

    public async Task<IdentityResult> CreateRoleAsync(string name)
    {
        // Check is the role exist
        var roleExist = await _roleManager.RoleExistsAsync(name);

        if (!roleExist)
        {
            var roleResult = await _roleManager.CreateAsync(new ApplicationRole(name));
            
            if (roleResult.Succeeded)
            {
                return roleResult;
            }
            else
            {
                throw new Exception($"The role {name} has not been added");
            }
        }

        throw new Exception("Role already exist");
        
    }

    public async Task<IdentityResult> UpdateRoleAsync(string id, RoleModel model)
    {
        var findRole = await _roleManager.FindByIdAsync(id);
        if (findRole != null)
        {
            findRole.Name = model.Name;
            var roleResult = await _roleManager.UpdateAsync(findRole);
            if (roleResult.Succeeded)
            {
                return roleResult;
            }
            else
            {
                throw new Exception($"The role {model.Name} has not been updated");
            }
        }
        else
        {
            throw new Exception("The role not founded");
        }
    }
    public async Task<bool> DeleteRole(string id)
    {
        var findRole = await _roleManager.FindByIdAsync(id);
        if (findRole == null) throw new Exception("The role not founded");
        await _roleManager.DeleteAsync(findRole);
        return true;

    }

   
}