using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;
using Microsoft.AspNetCore.Identity;

namespace IdsTemp.Core.IRepositories;

public interface IUserRepository
{
    Task<PaginatedList<UserModel>> GetAllUserAsync (string sortProperty, SortOrder sortOrder, string searchText="", int pageIndex = 1, int pageSize = 5);
    Task<UserModel> GetUserAsync(string id);
    Task<IdentityResult> CreateUserAsync(UserCreateModel user);
    Task<IdentityResult> EditUserAsync(string id, UserEditModel model);
    Task<bool> DeleteUser(string id);
}