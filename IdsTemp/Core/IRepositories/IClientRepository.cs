using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;

namespace IdsTemp.Core.IRepositories;

public interface IClientRepository
{
    Task<PaginatedList<ClientSummaryModel>> GetAllAsync(string searchText="", int pageIndex = 1, int pageSize = 5);
    Task<ClientModel> GetByIdAsync(string id);
    Task CreateAsync(CreateClientModel model);
    Task UpdateAsync(ClientModel model);
    Task DeleteAsync(string clientId);
}