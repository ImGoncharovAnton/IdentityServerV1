using IdsTemp.Models.AdminPanel;

namespace IdsTemp.Core.IRepositories;

public interface IClientRepository
{
    Task<IEnumerable<ClientSummaryModel>> GetAllAsync(string filter = null);
    Task<ClientModel> GetByIdAsync(string id);
    Task CreateAsync(CreateClientModel model);
    Task UpdateAsync(ClientModel model);
    Task DeleteAsync(string clientId);
}