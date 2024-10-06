using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OICAuth.API.Controllers
{
    [ApiController]
    public class AuthorizeController : ControllerBase
    {
        private static ClaimsIdentity Identity = new ClaimsIdentity();
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthorizeController(IOpenIddictApplicationManager applicationManager, IOpenIddictAuthorizationManager authorizationManager, IOpenIddictScopeManager scopeManager, SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
        {
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("~/api/connect/token")]
        public async Task<IActionResult> ConnectToken()
        {
            try
            {
                try
                {
                    var hcp = HttpContext.GetOpenIddictServerRequest();
                }
                catch (Exception ex)
                {

                    throw;
                }
                var openIdConnectRequest = HttpContext.GetOpenIddictServerRequest() ??
                         throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                Identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
                IdentityUser? user = null;
                AuthenticationProperties properties = new();

                if (openIdConnectRequest.IsClientCredentialsGrantType())
                {
                    Identity.SetScopes(openIdConnectRequest.GetScopes());
                    Identity.SetResources(await _scopeManager.ListResourcesAsync(Identity.GetScopes()).ToListAsync());

                    // Add mandatory Claims
                    Identity.AddClaim(new Claim(Claims.Subject, openIdConnectRequest.ClientId));
                    Identity.AddClaim(new Claim(Claims.Audience, "Resourse"));

                    Identity.SetDestinations(GetDestinations);


                }
                else if (openIdConnectRequest.IsPasswordGrantType())
                {
                    user = await _userManager.FindByNameAsync(openIdConnectRequest.Username);

                    if (user == null)
                    {
                        //return BadRequest(new OpenIddictResponse
                        //{
                        //    Error = Errors.InvalidGrant,
                        //    ErrorDescription = "User does not exist"
                        //});
                            properties = new AuthenticationProperties(new Dictionary<string, string>
                            {
                                [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                                    OpenIddictConstants.Errors.InvalidGrant,
                                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                    "The username/password couple is invalid."
                            });
                            Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                            throw new Exception("The username/password couple is invalid.");
                    }

                    // Check that the user can sign in and is not locked out.
                    // If two-factor authentication is supported, it would also be appropriate to check that 2FA is enabled for the user
                    if (!await _signInManager.CanSignInAsync(user) || (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user)))
                    {
                        // Return bad request is the user can't sign in
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = OpenIddictConstants.Errors.InvalidGrant,
                            ErrorDescription = "The specified user cannot sign in."
                        });
                    }

                    // Validate the username/password parameters and ensure the account is not locked out.
                    var result = await _signInManager.PasswordSignInAsync(user.UserName, openIdConnectRequest.Password, false, lockoutOnFailure: false);
                    if (!result.Succeeded)
                    {
                        if (result.IsNotAllowed)
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "User not allowed to login. Please confirm your email"
                            });
                        }

                        if (result.RequiresTwoFactor)
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "User requires 2F authentication"
                            });
                        }

                        if (result.IsLockedOut)
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "User is locked out"
                            });
                        }
                        else
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "Username or password is incorrect"
                            });
                        }
                    }

                    // The user is now validated, so reset lockout counts, if necessary
                    if (_userManager.SupportsUserLockout)
                    {
                        await _userManager.ResetAccessFailedCountAsync(user);
                    }

                    //// Getting scopes from user parameters (TokenViewModel) and adding in Identity 
                    Identity.SetScopes(openIdConnectRequest.GetScopes());

                    // Getting scopes from user parameters (TokenViewModel)
                    // Checking in OpenIddictScopes tables for matching resources
                    // Adding in Identity
                    Identity.SetResources(await _scopeManager.ListResourcesAsync(Identity.GetScopes()).ToListAsync());


                    //// Getting scopes from user parameters (TokenViewModel) and adding in Identity 
                    Identity.SetScopes(openIdConnectRequest.GetScopes());

                    //// You have to grant the 'offline_access' scope to allow
                    //// OpenIddict to return a refresh token to the caller.
                    if (!String.IsNullOrEmpty(openIdConnectRequest.Scope.ToString()) && openIdConnectRequest.Scope.Split(' ').Contains(OpenIddictConstants.Scopes.OfflineAccess))
                        Identity.SetScopes(OpenIddictConstants.Scopes.OfflineAccess);

                    // Add Custom claims
                    // sub claims is mendatory
                    Identity.AddClaim(new Claim(Claims.Subject, user.Id));
                    Identity.AddClaim(new Claim(Claims.Audience, "Resourse"));

                    // Setting destinations of claims i.e. identity token or access token
                    Identity.SetDestinations(GetDestinations);
                }
                else if (openIdConnectRequest.IsRefreshTokenGrantType())
                {
                    // Retrieve the claims principal stored in the authorization code/refresh token.
                    var authenticateResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                    if (authenticateResult.Succeeded && authenticateResult.Principal != null)
                    {
                        // Retrieve the user profile corresponding to the authorization code/refresh token.
                        user = await _userManager.FindByIdAsync(authenticateResult.Principal.GetClaim(Claims.Subject));
                        if (user is null)
                        {
                            return BadRequest(new OpenIddictResponse
                            {
                                Error = Errors.InvalidGrant,
                                ErrorDescription = "The token is no longer valid."
                            });
                        }

                        // You have to grant the 'offline_access' scope to allow
                        // OpenIddict to return a refresh token to the caller.
                        Identity.SetScopes(OpenIddictConstants.Scopes.OfflineAccess);

                        Identity.AddClaim(new Claim(Claims.Subject, user.Id));
                        Identity.AddClaim(new Claim(Claims.Audience, "Resourse"));

                        // Getting scopes from user parameters (TokenViewModel)
                        // Checking in OpenIddictScopes tables for matching resources
                        // Adding in Identity
                        Identity.SetResources(await _scopeManager.ListResourcesAsync(Identity.GetScopes()).ToListAsync());

                        // Setting destinations of claims i.e. identity token or access token
                        Identity.SetDestinations(GetDestinations);
                    }
                    else if (authenticateResult.Failure is not null)
                    {
                        var failureMessage = authenticateResult.Failure.Message;
                        var failureException = authenticateResult.Failure.InnerException;
                        return BadRequest(new OpenIddictResponse
                        {
                            Error = Errors.InvalidRequest,
                            ErrorDescription = failureMessage + failureException
                        });
                    }
                }
                else
                {
                    return BadRequest(new
                    {
                        error = Errors.UnsupportedGrantType,
                        error_description = "The specified grant type is not supported."
                    });
                }

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
                var signInResult = SignIn(new ClaimsPrincipal(Identity), properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                return signInResult;
            }
            catch (Exception ex)
            {
                return BadRequest(new OpenIddictResponse()
                {
                    Error = Errors.ServerError,
                    ErrorDescription = "Invalid login attempt"
                });
            }
        }


        [HttpPost]
        [Route("abcd")]
        public async Task<IActionResult> ABCD()
        {
            return Ok();
        }

        #region Private Methods

        private static IEnumerable<string> GetDestinations(Claim claim)
        {
            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            return claim.Type switch
            {
                Claims.Name or
                Claims.Subject
                   => new[] { Destinations.AccessToken, Destinations.IdentityToken },

                _ => new[] { Destinations.AccessToken },
            };
        }

        #endregion

    }
}
