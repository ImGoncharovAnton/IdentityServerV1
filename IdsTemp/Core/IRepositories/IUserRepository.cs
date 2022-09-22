using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;
using Microsoft.AspNetCore.Identity;

namespace IdsTemp.Core.IRepositories;

public interface IUserRepository
{
    Task<IEnumerable<UserModel>> GetAllUserAsync (string filter = null);
    Task<UserModel> GetUserAsync(string id);
    Task<IdentityResult> CreateUserAsync(UserCreateModel user);
    Task<IdentityResult> EditUserAsync(string id, UserEditModel model);
    Task<bool> DeleteUser(string id);
}