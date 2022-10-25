using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Entities;
using Duende.IdentityServer.EntityFramework.Mappers;
using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Core.Repositories;

public class IdentityScopeRepository : IIdentityScopeRepository
{
    private readonly ConfigurationDbContext _context;

    public IdentityScopeRepository(ConfigurationDbContext context)
    {
        _context = context;
    }
    
    public async Task<PaginatedList<IdentityScopeSummaryModel>> GetAllAsync(string searchText="", int pageIndex = 1, int pageSize = 5)
    {
        var query = _context.IdentityResources
            .Include(x => x.UserClaims)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(searchText))
        {
            query = query.Where(x => x.Name.Contains(searchText) || x.DisplayName.Contains(searchText));
        }

        var identityScopesModel = query.Select(x => new IdentityScopeSummaryModel
        {
            Name = x.Name,
            DisplayName = x.DisplayName
        });
        
        var identityScopes = await identityScopesModel.ToListAsync();
        
        var resRoles = new PaginatedList<IdentityScopeSummaryModel>(identityScopes, pageIndex, pageSize);
        
        return resRoles;
    }

    public async Task<IdentityScopeModel> GetByIdAsync(string id)
    {
        var scope = await _context.IdentityResources
            .Include(x => x.UserClaims)
            .SingleOrDefaultAsync(x => x.Name == id);

        if (scope == null) return null;

        return new IdentityScopeModel
        {
            Name = scope.Name,
            DisplayName = scope.DisplayName,
            UserClaims = scope.UserClaims.Any()
                ? scope.UserClaims.Select(x => x.Type).Aggregate((a, b) => $"{a} {b}")
                : null,
        };
    }

    public async Task CreateAsync(IdentityScopeModel model)
    {
        var scope = new Duende.IdentityServer.Models.IdentityResource()
        {
            Name = model.Name,
            DisplayName = model.DisplayName?.Trim()
        };

        var claims = model.UserClaims?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToArray() ??
                     Enumerable.Empty<string>();
        if (claims.Any())
        {
            scope.UserClaims = claims.ToList();
        }

        _context.IdentityResources.Add(scope.ToEntity());
        await _context.SaveChangesAsync();
    }

    public async Task UpdateAsync(IdentityScopeModel model)
    {
        var scope = await _context.IdentityResources
            .Include(x => x.UserClaims)
            .SingleOrDefaultAsync(x => x.Name == model.Name);

        if (scope == null) throw new Exception("Invalid Identity Scope");

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
            scope.UserClaims.AddRange(claimsToAdd.Select(x => new IdentityResourceClaim
            {
                Type = x,
            }));
        }

        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(string id)
    {
        var scope = await _context.IdentityResources.SingleOrDefaultAsync(x => x.Name == id);

        if (scope == null) throw new Exception("Invalid Identity Scope");

        _context.IdentityResources.Remove(scope);
        await _context.SaveChangesAsync();
    }
}