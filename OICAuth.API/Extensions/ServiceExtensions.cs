using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OICAuth.API.Data;
using OpenIddict.Client;

namespace OICAuth.API.Extensions
{
    public static class ServiceExtensions
    {

        public static IServiceCollection AddDBExtention(this IServiceCollection services, ConfigurationManager Configuration)
        {
            // Replace with your connection string.
            //            var connectionString = Configuration["ConnectionStrings:Default"];

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("AuthDbConnection"));

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need
                // to replace the default OpenIddict entities.
                //options.UseOpenIddict();

                // Add Openiddict
                options.UseOpenIddict();
            });


            return services;
        }
        public static IServiceCollection AddIdentityExtention(this IServiceCollection services)
        {
            services.AddIdentity<IdentityUser, IdentityRole>()
                 .AddEntityFrameworkStores<ApplicationDbContext>()
                 .AddDefaultTokenProviders();


            return services;
        }
        public static IServiceCollection AddOpenIddictExtention(this IServiceCollection services)
        {
            services.AddCors();
            services.AddOpenIddict()
                  .AddCore(coreOptions =>
                  {
                      coreOptions.UseEntityFrameworkCore()
                                  .UseDbContext<ApplicationDbContext>();
                  })
                  .AddServer(options =>
                  {
                      options.AllowClientCredentialsFlow()
                             .AllowRefreshTokenFlow();

                      options.AllowPasswordFlow()
                             .AllowRefreshTokenFlow();

                      // Encryption and signing of tokens
                      options
                            .AddDevelopmentEncryptionCertificate()
                            .AddDevelopmentSigningCertificate()
                            .DisableAccessTokenEncryption();

                      // Register the ASP.NET Core host and configure the ASP.NET Core options.
                      options.UseAspNetCore()
                               .EnableTokenEndpointPassthrough()
                               .EnableAuthorizationEndpointPassthrough()
                               .EnableLogoutEndpointPassthrough()
                               .DisableTransportSecurityRequirement();

                      // Adding Token url

                      options.SetTokenEndpointUris("api/connect/token")
                              .SetAuthorizationEndpointUris("/api/connect/authorize")
                              .SetIntrospectionEndpointUris("/connect/introspect")
                              .SetLogoutEndpointUris("/api/connect/logout");

                      options.AllowAuthorizationCodeFlow()
                        .AllowClientCredentialsFlow()
                        .AllowPasswordFlow()
                        .AllowRefreshTokenFlow();



                      options.UseAspNetCore()
                        .EnableTokenEndpointPassthrough()
                        .EnableLogoutEndpointPassthrough()
                        .EnableTokenEndpointPassthrough()
                        .EnableUserinfoEndpointPassthrough()
                        //.DisableTransportSecurityRequirement() //need to remove
                        .EnableStatusCodePagesIntegration();


                  //}).AddValidation(options =>
                  //{
                  //    // Import the configuration from the local OpenIddict server instance.
                  //    options.UseLocalServer();

                  //    // Register the ASP.NET Core host.
                  //    //options.UseAspNetCore();
                  });


            return services;
        }

    }
}
