using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Identity;

namespace IdsTemp.Core.IRepositories;

public interface IRoleRepository
{
    Task <ICollection<RoleModel>> GetRolesAsync(string filter = null);
    Task<RoleModel> GetRoleAsync(string id);
    Task<IdentityResult> CreateRoleAsync(string name);
    Task<IdentityResult> UpdateRoleAsync(string id, RoleModel model);
    Task<bool> DeleteRole(string id);
}