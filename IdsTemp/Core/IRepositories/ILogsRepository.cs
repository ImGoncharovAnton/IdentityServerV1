using IdsTemp.Models;
using IdsTemp.Models.Common;

namespace IdsTemp.Core.IRepositories;

public interface ILogsRepository
{
    Task<List<LogEntity>> GetItemsAsync(string sortProperty, SortOrder sortOrder, string searchText="");
    Task<bool> DeleteRangeAsync(string id);
}