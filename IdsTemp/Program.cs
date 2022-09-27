using System.Security.Claims;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using IdentityModel;
using IdsTemp;
using IdsTemp.Data;
using IdsTemp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting up");

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(
            outputTemplate:
            "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
        .Enrich.FromLogContext()
        .ReadFrom.Configuration(ctx.Configuration));

    var app = builder
        .ConfigureServices()
        .ConfigurePipeline();
    
    using var scope = app.Services.CreateScope();

    await scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.MigrateAsync();
    var configurationContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
    await configurationContext.Database.MigrateAsync();
    await scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.MigrateAsync();

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
    
    if (roleManager.FindByNameAsync("ISAdministrator").Result == null)
    {
        roleManager.CreateAsync(new ApplicationRole("ISAdministrator")).GetAwaiter().GetResult();
    }
    
    var iSAdmin = userManager.FindByNameAsync("ISAdmin").Result;

    if (iSAdmin == null)
    {
        iSAdmin = new ApplicationUser
        {
            UserName = "ISAdmin",
            Email = "isadmin@example",
            FirstName = "Identity",
            LastName = "Admin"
        };
        var result = userManager.CreateAsync(iSAdmin, "PE30.zAq123").Result;
        result = userManager.AddToRoleAsync(iSAdmin, "ISAdministrator").Result;
        Log.Information("Done seeding isAdmin");
        if (!result.Succeeded)
        {
            throw new Exception(result.Errors.First().Description);
        }

        result = userManager.AddClaimsAsync(iSAdmin, new Claim[]
        {
            new Claim(JwtClaimTypes.Role, "ISAdministrator")
        }).Result;
        if (!result.Succeeded)
        {
            throw new Exception(result.Errors.First().Description);
        }
    }
    
    if (!configurationContext.IdentityResources.Any())
    {
        Log.Debug("IdentityResources being populated");
        foreach (var resource in Config.IdentityResources.ToList())
        {
            configurationContext.IdentityResources.Add(resource.ToEntity());
        }

        configurationContext.SaveChanges();
    }
    else
    {
        Log.Debug("IdentityResources already populated");
    }

    // this seeding is only for the template to bootstrap the DB and users.
    // in production you will likely want a different approach.
    if (args.Contains("/seed"))
    {
        Log.Information("Seeding database...");
        SeedData.EnsureSeedData(app);
        Log.Information("Done seeding database. Exiting.");
        return;
    }

    app.Run();
}
catch (Exception ex) when
    (ex.GetType().Name is not "StopTheHostException") // https://github.com/dotnet/runtime/issues/60600
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.Information("Shut down complete");
    Log.CloseAndFlush();
}