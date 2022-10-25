using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;

namespace IdsTemp.Core.IRepositories;

public interface IIdentityScopeRepository
{
    Task<PaginatedList<IdentityScopeSummaryModel>> GetAllAsync(string searchText="", int pageIndex = 1, int pageSize = 5);
    Task<IdentityScopeModel> GetByIdAsync(string id);
    Task CreateAsync(IdentityScopeModel model);
    Task UpdateAsync(IdentityScopeModel model);
    Task DeleteAsync(string id);
}