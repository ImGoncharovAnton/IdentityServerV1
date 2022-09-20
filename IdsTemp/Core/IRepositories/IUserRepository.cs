using IdsTemp.Models;
using IdsTemp.Models.AdminPanel;

namespace IdsTemp.Core.IRepositories;

public interface IUserRepository
{
    Task<IEnumerable<UserModel>> GetAllUserAsync (string filter = null);
}