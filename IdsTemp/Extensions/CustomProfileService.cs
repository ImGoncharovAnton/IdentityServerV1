using System.Security.Claims;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using IdsTemp.Models;
using Microsoft.AspNetCore.Identity;

namespace IdsTemp.Extensions;

public class CustomProfileService : IProfileService
{
    private readonly IUserClaimsPrincipalFactory<ApplicationUser> _userClaimsPrincipalFactory;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _rolemanager;

    public CustomProfileService(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> rolemanager,
        IUserClaimsPrincipalFactory<ApplicationUser> userClaimsPrincipalFactory)
    {
        _userManager = userManager;
        _rolemanager = rolemanager;
        _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
    }
    
    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        string sub = context.Subject.GetSubjectId();
        ApplicationUser user = await _userManager.FindByIdAsync(sub);

        ClaimsPrincipal userClaims = await _userClaimsPrincipalFactory.CreateAsync(user);

        List<Claim> claims = userClaims.Claims.ToList();
        claims = claims.Where(u => context.RequestedClaimTypes.Contains(u.Type)).ToList();
        claims.Add(new Claim(JwtClaimTypes.Email, user.Email));
        if (_userManager.SupportsUserRole)
        {
            IList<string> roles = await _userManager.GetRolesAsync(user);
            foreach (var rolename in roles)
            {
                claims.Add(new Claim(JwtClaimTypes.Role, rolename));
            }
        }

        context.IssuedClaims = claims;
    }

    public async Task IsActiveAsync(IsActiveContext context)
    {
        string sub = context.Subject.GetSubjectId();
        ApplicationUser user = await _userManager.FindByIdAsync(sub);
        context.IsActive = user != null;
    }
    
}