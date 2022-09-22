﻿using Duende.IdentityServer.EntityFramework.Entities;
using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.AdminPanel;

public class ClientModel: CreateClientModel, IValidatableObject
{
    [Required]
    public string? AllowedScopes { get; set; }
    public string? RedirectUri { get; set; }
    public string? PostLogoutRedirectUri { get; set; }
    public string? FrontChannelLogoutUri { get; set; }
    public string? BackChannelLogoutUri { get; set; }
    //
    public bool RequirePkce { get; set; }
    public bool AllowAccessTokensViaBrowser { get; set; }
    public string? AllowedCorsOrigins { get; set; }
    public bool RequireConsent { get; set; }
    public int AccessTokenLifetime { get; set; }
    //

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        var errors = new List<ValidationResult>();

        if (Flow != Flow.CodeFlowWithPkce) return errors;
        if (RedirectUri == null)
        {
            errors.Add(new ValidationResult("Redirect URI is required.", new[] { "RedirectUri" }));
        }

        return errors;
    }
}