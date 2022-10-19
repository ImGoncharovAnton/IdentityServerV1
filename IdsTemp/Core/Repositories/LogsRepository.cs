using IdsTemp.Core.IRepositories;
using IdsTemp.Data;
using IdsTemp.Models;
using IdsTemp.Models.Common;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Core.Repositories;

public class LogsRepository: ILogsRepository
{
    private readonly ApplicationDbContext _dbContext;

    public LogsRepository(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<List<LogEntity>> GetItemsAsync(string sortProperty, SortOrder sortOrder, string searchText = "")
    {
        /*var logs = from l in _dbContext.logs
            select l;*/

        List<LogEntity> logs;

        if (!string.IsNullOrEmpty(searchText))
        {
            logs = await _dbContext.logs
                .Where(m => m.message.Contains(searchText) || m.exception.Contains(searchText))
                .ToListAsync();
        }
        else
        {
            logs = await _dbContext.logs.ToListAsync();
        }
        
        logs = DoSort(logs, sortProperty, sortOrder);
        
        return logs;
    }

    public async Task<bool> DeleteRangeAsync(string id)
    {
        throw new NotImplementedException();
    }

    private List<LogEntity> DoSort(List<LogEntity> logs, string sortProperty, SortOrder sortOrder)
    {
        

        if (sortProperty.ToLower() == "timestamp")
        {
            if (sortOrder == SortOrder.Ascending)
                logs = logs.OrderBy(n => n.timestamp).ToList();
            else
                logs = logs.OrderByDescending(n => n.timestamp).ToList();
        }
        else
        {
            if (sortOrder == SortOrder.Ascending)
                logs = logs.OrderBy(l => l.level).ToList();
            else
                logs = logs.OrderByDescending(l => l.level).ToList();
        }

        var result = logs;
        return result;
    }
}