using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Entities;
using Duende.IdentityServer.EntityFramework.Mappers;
using IdsTemp.Models;
using IdsTemp.Models.Admin;
using Microsoft.EntityFrameworkCore;
using ApiScope = Duende.IdentityServer.Models.ApiScope;

namespace IdsTemp.Repositories;

public class ApiScopeRepository
{
    private readonly ConfigurationDbContext _configurationDbcontext;

    public ApiScopeRepository(ConfigurationDbContext configurationDb)
    {
        _configurationDbcontext = configurationDb;
    }

    public async Task<IEnumerable<ApiScopeSummaryModel>> GetAllAsync(string filter = null)
    {
        var query = _configurationDbcontext.ApiScopes
            .Include(x => x.UserClaims)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(filter))
        {
            query = query.Where(x => x.Name.Contains(filter) || x.DisplayName.Contains(filter));
        }

        var result = query.Select(x => new ApiScopeModel
        {
            Name = x.Name,
            DisplayName = x.DisplayName
        });

        return await result.ToArrayAsync();
    }

    public async Task<ApiScopeModel> GetByIdAsync(string id)
    {
        var apiScope = await _configurationDbcontext.ApiScopes
            .Include(x => x.UserClaims)
            .SingleOrDefaultAsync(x => x.Name == id);

        if (apiScope == null) return null;

        return new ApiScopeModel
        {
            Name = apiScope.Name,
            DisplayName = apiScope.DisplayName,
            UserClaims = apiScope.UserClaims.Any()
            ? apiScope.UserClaims.Select(x => x.Type).Aggregate((a, b) => $"{a} {b}") : null
        };
    }

    public async Task CreateAsync(ApiScopeModel model)
    {
        var apiScope = new ApiScope
        {
            Name = model.Name,
            DisplayName = model.DisplayName?.Trim()
        };

        var claims = model.UserClaims?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToArray() ??
                     Enumerable.Empty<string>();
        if (claims.Any())
        {
            apiScope.UserClaims = claims.ToList();
        }

        _configurationDbcontext.ApiScopes.Add(apiScope.ToEntity());
        await _configurationDbcontext.SaveChangesAsync();
    }

    public async Task UpdateAsync(ApiScopeModel model)
    {
        var scope = await _configurationDbcontext.ApiScopes
            .Include(x => x.UserClaims)
            .SingleOrDefaultAsync(x => x.Name == model.Name);

        if (scope == null) throw new Exception("Invalid Api Scope");

        if (scope.DisplayName != model.DisplayName)
        {
            scope.DisplayName = model.DisplayName?.Trim();
        }

        var claims = model.UserClaims?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToArray() ??
                     Enumerable.Empty<string>();
        var currentClaims = (scope.UserClaims.Select(x => x.Type) ?? Enumerable.Empty<String>()).ToArray();

        var claimsToAdd = claims.Except(currentClaims).ToArray();
        var claimsToRemove = currentClaims.Except(claims).ToArray();

        if (claimsToRemove.Any())
        {
            scope.UserClaims.RemoveAll(x => claimsToRemove.Contains(x.Type));
        }

        if (claimsToAdd.Any())
        {
            scope.UserClaims.AddRange(claimsToAdd.Select(x => new ApiScopeClaim
            {
                Type = x,
            }));
        }

        await _configurationDbcontext.SaveChangesAsync();
    }
    
    public async Task DeleteAsync(string id)
    {
        var scope = await _configurationDbcontext.ApiScopes.SingleOrDefaultAsync(x => x.Name == id);

        if (scope == null) throw new Exception("Invalid Api Scope");

        _configurationDbcontext.ApiScopes.Remove(scope);
        await _configurationDbcontext.SaveChangesAsync();
    }
}