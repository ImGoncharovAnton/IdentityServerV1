using Duende.IdentityServer;
using IdsTemp.Core.IRepositories;
using IdsTemp.Core.Repositories;
using IdsTemp.Data;
using IdsTemp.Extensions;
using IdsTemp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Serilog;

namespace IdsTemp;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        // builder.Services.AddRazorPages();

        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        builder.Services
            .AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;
            })
            .AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = b =>
                    b.UseSqlServer(connectionString,
                        dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
            })
            // this is something you will want in production to reduce load on and requests to the DB
            //.AddConfigurationStoreCache()
            //
            // this adds the operational data from DB (codes, tokens, consents)
            .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = b =>
                    b.UseSqlServer(connectionString,
                        dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));

                // this enables automatic token cleanup. this is optional.
                options.EnableTokenCleanup = true;
                options.RemoveConsumedTokens = true;
            })
            .AddAspNetIdentity<ApplicationUser>()
            .AddProfileService<CustomProfileService>();;

        // builder.Services.AddAuthentication()
        //     .AddGoogle(options =>
        //     {
        //         options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        //
        //         // register your IdentityServer with Google at https://console.developers.google.com
        //         // enable the Google+ API
        //         // set the redirect URI to https://localhost:5001/signin-google
        //         options.ClientId = "copy client ID from Google here";
        //         options.ClientSecret = "copy client secret from Google here";
        //     });

        builder.Services.ConfigureApplicationCookie(config =>
        {
            config.Cookie.Name = "IdentityServer.Cookie";
            // config.LoginPath = "/Auth/Login";
            // config.LogoutPath = "/Auth/Logout";
        });

        builder.Services.AddControllersWithViews();
        builder.Services.AddTransient<IApiScopeRepository, ApiScopeRepository>();
        builder.Services.AddTransient<IClientRepository, ClientRepository>();
        builder.Services.AddTransient<IIdentityScopeRepository, IdentityScopeRepository>();
        builder.Services.AddTransient<IRoleRepository, RoleRepository>();
        builder.Services.AddTransient<IUserRepository, UserRepository>();
        
        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Home/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthentication();
        app.UseAuthorization();

        //  Не уверен, надо ли
        // app.MapRazorPages()
        //     .RequireAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllerRoute(
                name: "MyArea",
                pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");
            endpoints.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");
        });
        
        return app;
    }
}