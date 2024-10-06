using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace OICAuth.API.Data
{
    public class SeedClientData : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;
        public SeedClientData(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }
        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("Test", cancellationToken) is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "Test",
                    ClientSecret = "test123",
                    DisplayName = "Test",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.GrantTypes.Password,
                        OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                        OpenIddictConstants.Permissions.Scopes.Email,
                        OpenIddictConstants.Permissions.Scopes.Profile,
                        OpenIddictConstants.Permissions.Scopes.Roles,
                        OpenIddictConstants.Permissions.Endpoints.Introspection
                        

                        //OpenIddictConstants.Permissions.Prefixes.Scope + "api"
                    }
                }, cancellationToken);
            }
            //if (await manager.FindByClientIdAsync("Client1", cancellationToken) is null)
            //{
            //    await manager.CreateAsync(new OpenIddictApplicationDescriptor
            //    {
            //        ClientId = "Client1",
            //        ClientSecret = "client123",
            //        DisplayName = "Client1",
            //        Permissions =
            //        {
            //            OpenIddictConstants.Permissions.Endpoints.Introspection
            //        }
            //    }, cancellationToken);
            //}
            //if (await manager.FindByClientIdAsync("Client2", cancellationToken) is null)
            //{
            //    await manager.CreateAsync(new OpenIddictApplicationDescriptor
            //    {
            //        ClientId = "Client2",
            //        ClientSecret = "client123",
            //        DisplayName = "Client2",
            //        Permissions =
            //        {
            //            OpenIddictConstants.Permissions.Endpoints.Introspection
            //        }
            //    }, cancellationToken);
            //}

            var _userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var _roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            var loguser = _userManager.FindByEmailAsync("admin@example.com");
            if (loguser.Result == null)
            {
                var isHave = await _roleManager.RoleExistsAsync("Admin");
                if (!isHave)
                {
                    var newRole = new IdentityRole()
                    {
                        Name = "Admin"
                    };
                    await _roleManager.CreateAsync(newRole);
                }
                var user1 = new IdentityUser
                {
                    UserName = "admin@example.com",
                    Email = "admin@example.com",
                    PhoneNumber = "0123456789",
                };
                var password = "SystemGenerated@123";
                await _userManager.CreateAsync(user1, password);
                await _userManager.AddToRoleAsync(user1, "Admin");

            }
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
