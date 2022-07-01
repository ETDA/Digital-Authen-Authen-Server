using IdentityServer4;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.IdentityConfiguration
{
    public class Resources
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new[]
            {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResource
            {
                Name = "role",
                UserClaims = new List<string> {"role"}
            }
        };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new[]
            {
            new ApiResource
            {
                Name = "BackOfficeApi",
                DisplayName = "BackOffice Api",
                Description = "Allow the application to access BackOffice Api on your behalf",
                Scopes = new List<string> { "backofficeApi.read"},
                ApiSecrets = new List<Secret> {new Secret("2PD0BM3CNX1f0phU".Sha256())},
                UserClaims = new List<string> {"role"}
            },
            new ApiResource
            {
                Name = "BackOfficeTest",
                DisplayName = "Back Office Web",
                Description = "Allow the application to access BackOfficeTest on your behalf",
                Scopes = new List<string> {  IdentityServerConstants.StandardScopes.OpenId,
                                             IdentityServerConstants.StandardScopes.Profile,
                                             IdentityServerConstants.StandardScopes.Email,
                                             "role",
                                             "backofficeApi.read"
                                          },
                ApiSecrets = new List<Secret> {new Secret("2PD0BM3CNX1f0phU".Sha256())},
                UserClaims = new List<string> {"role"}
            }
        };
        }
    }
}
