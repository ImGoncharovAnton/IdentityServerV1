using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;
using Microsoft.AspNetCore.Identity;

namespace IdsTemp.Core.IRepositories;

public interface IRoleRepository
{
    Task<PaginatedList<RoleModel>> GetRolesAsync(string searchText="", int pageIndex = 1, int pageSize = 5);
    Task<RoleModel> GetRoleAsync(string id);
    Task<string> GetRoleIdByName(string roleName);
    Task<IdentityResult> CreateRoleAsync(string name);
    Task<IdentityResult> UpdateRoleAsync(string id, RoleModel model);
    Task<bool> DeleteRole(string id);
}