using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;

namespace IdsTemp.Core.IRepositories;

public interface IApiScopeRepository
{
    Task<PaginatedList<ApiScopeSummaryModel>> GetAllAsync(string searchText="", int pageIndex = 1, int pageSize = 5);
    Task<ApiScopeModel> GetByIdAsync(string id);
    Task CreateAsync(ApiScopeModel model);
    Task UpdateAsync(ApiScopeModel model);
    Task DeleteAsync(string id);
}