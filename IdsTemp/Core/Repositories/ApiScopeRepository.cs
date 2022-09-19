using Duende.IdentityServer.EntityFramework.DbContexts;
using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Core.Repositories;

public class ApiScopeRepository : IApiScopeRepository
{

    private readonly ConfigurationDbContext _context;

    public ApiScopeRepository(ConfigurationDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<ApiScopeSummaryModel>> GetAllAsync(string filter = null)
    {
        var query = _context.ApiScopes
            .Include(x => x.UserClaims).AsQueryable();
        
        if (!String.IsNullOrWhiteSpace(filter))
        {
            query = query.Where(x => x.Name.Contains(filter) || x.DisplayName.Contains(filter));
        }
        
        var result = query.Select(x => new ApiScopeSummaryModel
        {
            Name = x.Name,
            DisplayName = x.DisplayName
        });
        
        return await result.ToListAsync();
    }
    
    public async Task<ApiScopeModel> GetByIdAsync(string id)
    {
        var scope = await _context.ApiScopes
            .Include(x => x.UserClaims)
            .SingleOrDefaultAsync(x => x.Name == id);

        if (scope == null) return null;

        return new ApiScopeModel
        {
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            UserClaims = scope.UserClaims.Any()
                ? scope.UserClaims.Select(x => x.Type).Aggregate((a, b) => $"{a} {b}")
                : null,
        };
    }
}