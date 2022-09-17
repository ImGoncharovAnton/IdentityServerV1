using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;

namespace IdsTemp;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
        {
            new ApiScope("inventory", "Inventory")
        };

    public static IEnumerable<Client> Clients =>
        new Client[]
        {
            // m2m client credentials flow client
            new Client
            {
                // machine to machine client
                ClientId = "inventory-api",
                ClientSecrets = { new Secret("secret".Sha256()) },
            
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                // scopes that client has access to
                AllowedScopes = { "inventory" }
            },

            // interactive SPA angular
            new Client
            {
                ClientName = "Angular-client",
                ClientId = "angular-client",
                ClientSecrets = { new Secret("7A622350-FB10-427C-BCC1-723253A4B3FD".Sha256())},
                AllowedGrantTypes = GrantTypes.Code,
                RedirectUris = new List<string> { "http://localhost:4200/signin-callback", "http://localhost:4200/assets/silent-callback.html" },
                RequirePkce = true,
                AllowAccessTokensViaBrowser = true,
                AllowedScopes =
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    "inventory",
                    JwtClaimTypes.Role
                },
                AllowedCorsOrigins = { "http://localhost:4200" },
                RequireClientSecret = false,
                AllowOfflineAccess = true,
                PostLogoutRedirectUris = new List<string> { "http://localhost:4200/signout-callback" },
                RequireConsent = false,
                AccessTokenLifetime = 1800
            }
        };
}