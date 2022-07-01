using IdentityServer4;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.IdentityConfiguration
{
    public class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new List<Client>
        {
            new Client
            {
                ClientId = "TestApi",
                ClientName = "Test Api",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = new List<Secret> {new Secret("secret".Sha256())},
                AllowedScopes = new List<string> { "testApi.read" }
            },
            new Client
            {
                ClientId = "Test",
                ClientName = "Test",
                ClientSecrets = new List<Secret> {new Secret("secret".Sha256())},

                AllowedGrantTypes = GrantTypes.Code,
                RedirectUris = new List<string> {"https://domain/callback" },
                PostLogoutRedirectUris = { "https://domain/logout" },
                AllowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "role",
                    "testApi.read"
                }
            }
        };
        }
    }
}
