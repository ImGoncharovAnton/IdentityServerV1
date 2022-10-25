﻿using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Entities;
using Duende.IdentityServer.EntityFramework.Mappers;
using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using IdsTemp.Models.Common;
using Microsoft.EntityFrameworkCore;
using ApiScope = Duende.IdentityServer.Models.ApiScope;

namespace IdsTemp.Core.Repositories;

public class ApiScopeRepository : IApiScopeRepository
{

    private readonly ConfigurationDbContext _context;

    public ApiScopeRepository(ConfigurationDbContext context)
    {
        _context = context;
    }

    public async Task<PaginatedList<ApiScopeSummaryModel>> GetAllAsync(string searchText="", int pageIndex = 1, int pageSize = 5)
    {
        var query = _context.ApiScopes
            .Include(x => x.UserClaims).AsQueryable();
        
        if (!String.IsNullOrWhiteSpace(searchText))
        {
            query = query.Where(x => x.Name.Contains(searchText) || x.DisplayName.Contains(searchText));
        }
        
        var apiScopeModels = query.Select(x => new ApiScopeSummaryModel
        {
            Name = x.Name,
            DisplayName = x.DisplayName
        });
        
        var apiScopes = await apiScopeModels.ToListAsync();
        
        var resRoles = new PaginatedList<ApiScopeSummaryModel>(apiScopes, pageIndex, pageSize);
        
        return resRoles;
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

        _context.ApiScopes.Add(apiScope.ToEntity());
        await _context.SaveChangesAsync();
    }

    public async Task UpdateAsync(ApiScopeModel model)
    {
        var scope = await _context.ApiScopes
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

        await _context.SaveChangesAsync();
    }
    
    public async Task DeleteAsync(string id)
    {
        var scope = await _context.ApiScopes.SingleOrDefaultAsync(x => x.Name == id);

        if (scope == null) throw new Exception("Invalid Api Scope");

        _context.ApiScopes.Remove(scope);
        await _context.SaveChangesAsync();
    }
}