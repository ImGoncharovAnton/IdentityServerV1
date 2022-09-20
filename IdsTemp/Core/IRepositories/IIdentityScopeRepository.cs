using IdsTemp.Models.AdminPanel;

namespace IdsTemp.Core.IRepositories;

public interface IIdentityScopeRepository
{
    Task<IEnumerable<IdentityScopeSummaryModel>> GetAllAsync(string filter = null);
    Task<IdentityScopeModel> GetByIdAsync(string id);
    Task CreateAsync(IdentityScopeModel model);
    Task UpdateAsync(IdentityScopeModel model);
    Task DeleteAsync(string id);
}