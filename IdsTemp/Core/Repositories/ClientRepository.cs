using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Entities;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.Models;
using IdsTemp.Core.IRepositories;
using IdsTemp.Models.AdminPanel;
using Microsoft.EntityFrameworkCore;

namespace IdsTemp.Core.Repositories;

public class ClientRepository : IClientRepository
{
    private readonly ConfigurationDbContext _context;

    public ClientRepository(ConfigurationDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<ClientSummaryModel>> GetAllAsync(string filter = null)
    {
        var grants = new[] { GrantType.AuthorizationCode, GrantType.ClientCredentials };

        var query = _context.Clients
            .Include(x => x.AllowedGrantTypes)
            .Where(x => x.AllowedGrantTypes.Count == 1 &&
                        x.AllowedGrantTypes.Any(grant => grants.Contains(grant.GrantType)));

        if (!string.IsNullOrWhiteSpace(filter))
        {
            query = query.Where(x => x.ClientId.Contains(filter) || x.ClientName.Contains(filter));
        }

        var result = query.Select(x => new ClientSummaryModel
        {
            ClientId = x.ClientId,
            Name = x.ClientName,
            Flow = x.AllowedGrantTypes.Select(type => type.GrantType).Single() == GrantType.ClientCredentials
                ? Flow.ClientCredentials
                : Flow.CodeFlowWithPkce
        });

        return await result.ToArrayAsync();
    }

    public async Task<ClientModel> GetByIdAsync(string id)
    {
        var client = await _context.Clients
            .Include(x => x.AllowedGrantTypes)
            .Include(x => x.AllowedScopes)
            .Include(x => x.RedirectUris)
            .Include(x => x.PostLogoutRedirectUris)
            .Include(x => x.AllowedCorsOrigins)
            .Where(x => x.ClientId == id)
            .SingleOrDefaultAsync();

        if (client == null) return null;

        var model = new ClientModel
        {
            ClientId = client.ClientId,
            Name = client.ClientName,
            Flow = client.AllowedGrantTypes.Select(x => x.GrantType)
                .Single() == GrantType.ClientCredentials
                ? Flow.ClientCredentials
                : Flow.CodeFlowWithPkce,
            AllowedScopes = client.AllowedScopes.Any()
                ? client.AllowedScopes.Select(x => x.Scope).Aggregate((a, b) => $"{a} {b}")
                : null,
            RedirectUri = client.RedirectUris.Any()
                ? client.RedirectUris.Select(x => x.RedirectUri).Aggregate((a, b) => $"{a} {b}")
                : null,
            PostLogoutRedirectUri =
                client.PostLogoutRedirectUris.Select(x => x.PostLogoutRedirectUri).SingleOrDefault(),
            FrontChannelLogoutUri = client.FrontChannelLogoutUri,
            BackChannelLogoutUri = client.BackChannelLogoutUri,
            RequirePkce = client.RequirePkce,
            AllowAccessTokensViaBrowser = client.AllowAccessTokensViaBrowser,
            AllowedCorsOrigins = client.AllowedCorsOrigins.Any()
                ? client.AllowedCorsOrigins.Select(x => x.Origin).Aggregate((a, b) => $"{a} {b}")
                : null,
            RequireConsent = client.RequireConsent,
            AccessTokenLifetime = client.AccessTokenLifetime,
        };

        return model;
    }

    public async Task CreateAsync(CreateClientModel model)
    {
        var client = new Duende.IdentityServer.Models.Client();
        client.ClientId = model.ClientId.Trim();
        client.ClientName = model.Name?.Trim();

        client.ClientSecrets.Add(new Duende.IdentityServer.Models.Secret(model.Secret.Sha256()));

        if (model.Flow == Flow.ClientCredentials)
        {
            client.AllowedGrantTypes = GrantTypes.ClientCredentials;
        }
        else
        {
            client.AllowedGrantTypes = GrantTypes.Code;
            client.AllowOfflineAccess = true;
        }

        _context.Clients.Add(client.ToEntity());
        await _context.SaveChangesAsync();
    }

    public async Task UpdateAsync(ClientModel model)
    {
        var client = await _context.Clients
            .Include(x => x.AllowedGrantTypes)
            .Include(x => x.AllowedScopes)
            .Include(x => x.RedirectUris)
            .Include(x => x.PostLogoutRedirectUris)
            .Include(x => x.AllowedCorsOrigins)
            .SingleOrDefaultAsync(x => x.ClientId == model.ClientId);

        if (client == null) throw new Exception("Invalid Client Id");

        if (client.ClientName != model.Name)
        {
            client.ClientName = model.Name?.Trim();
        }

        if (client.AccessTokenLifetime != model.AccessTokenLifetime)
        {
            client.AccessTokenLifetime = model.AccessTokenLifetime;
        }
        
        var scopes = model.AllowedScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToArray();
        var currentScopes = (client.AllowedScopes.Select(x => x.Scope) ?? Enumerable.Empty<string>()).ToArray();

        var scopesToAdd = scopes.Except(currentScopes).ToArray();
        var scopesToRemove = currentScopes.Except(scopes).ToArray();

        if (scopesToRemove.Any())
        {
            client.AllowedScopes.RemoveAll(x => scopesToRemove.Contains(x.Scope));
        }

        if (scopesToAdd.Any())
        {
            client.AllowedScopes.AddRange(scopesToAdd.Select(x => new ClientScope
            {
                Scope = x,
            }));
        }

        var flow = client.AllowedGrantTypes.Select(x => x.GrantType)
            .Single() == GrantType.ClientCredentials
            ? Flow.ClientCredentials
            : Flow.CodeFlowWithPkce;

        if (flow == Flow.CodeFlowWithPkce)
        {
            
            if (client.AllowAccessTokensViaBrowser != model.AllowAccessTokensViaBrowser)
            {
                client.AllowAccessTokensViaBrowser = model.AllowAccessTokensViaBrowser;
            }

            if (client.RequireConsent != model.RequireConsent)
            {
                client.RequireConsent = model.RequireConsent;
            }
            
            if (model.AllowedCorsOrigins != null)
            {
                var cors = model.AllowedCorsOrigins.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToArray();
                var currentCors = (client.AllowedCorsOrigins.Select(x => x.Origin) ?? Enumerable.Empty<string>()).ToArray();

                var corsToAdd = cors.Except(currentCors).ToArray();
                var corsToRemove = currentCors.Except(cors).ToArray();

                if (corsToRemove.Any())
                {
                    client.AllowedCorsOrigins.RemoveAll(x => corsToRemove.Contains(x.Origin));
                }

                if (corsToAdd.Any())
                {
                    client.AllowedCorsOrigins.AddRange(corsToAdd.Select(x => new ClientCorsOrigin
                    {
                        Origin = x,
                    }));
                }
            }
            //
          /*  if (client.RedirectUris.FirstOrDefault()?.RedirectUri != model.RedirectUri)
            {
                client.RedirectUris.Clear();
                if (model.RedirectUri != null)
                {
                    client.RedirectUris.Add(new ClientRedirectUri { RedirectUri = model.RedirectUri.Trim() });
                }
            }*/

            var redirectUris = model.RedirectUri.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToArray();
            var currentRedirectUris = (client.RedirectUris.Select(x => x.RedirectUri) ?? Enumerable.Empty<string>()).ToArray();

            var redirectUrisToAdd = redirectUris.Except(currentRedirectUris).ToArray();
            var redirectUrisToRemove = currentRedirectUris.Except(redirectUris).ToArray();

            if (redirectUrisToRemove.Any())
            {
                client.RedirectUris.RemoveAll(x => redirectUrisToRemove.Contains(x.RedirectUri));
            }

            if (redirectUrisToAdd.Any())
            {
                client.RedirectUris.AddRange(redirectUrisToAdd.Select(x => new ClientRedirectUri
                {
                    RedirectUri = x,
                }));
            }

            //
            if (client.PostLogoutRedirectUris.FirstOrDefault()?.PostLogoutRedirectUri != model.PostLogoutRedirectUri)
            {
                client.PostLogoutRedirectUris.Clear();
                if (model.PostLogoutRedirectUri != null)
                {
                    client.PostLogoutRedirectUris.Add(new ClientPostLogoutRedirectUri
                        { PostLogoutRedirectUri = model.PostLogoutRedirectUri.Trim() });
                }
            }

            if (client.FrontChannelLogoutUri != model.FrontChannelLogoutUri)
            {
                client.FrontChannelLogoutUri = model.FrontChannelLogoutUri?.Trim();
            }

            if (client.BackChannelLogoutUri != model.BackChannelLogoutUri)
            {
                client.BackChannelLogoutUri = model.BackChannelLogoutUri?.Trim();
            }
        }

        await _context.SaveChangesAsync();
    }

    public async Task DeleteAsync(string clientId)
    {
        var client = await _context.Clients.SingleOrDefaultAsync(x => x.ClientId == clientId);

        if (client == null) throw new Exception("Invalid Client Id");

        _context.Clients.Remove(client);
        await _context.SaveChangesAsync();
    }
}