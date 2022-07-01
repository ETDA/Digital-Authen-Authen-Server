using IdentityModel;
using IdentityServer4.Test;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.IdentityConfiguration
{
    public class Users
    {
        public static List<TestUser> Get()
        {
            return new List<TestUser>
        {
            new TestUser
            {
                SubjectId = "GUID",
                Username = "testsyncfido@etda.or.th",
                Password = "l^8@#GF$YwVh",
                Claims = new List<Claim>
                {
                    new Claim(JwtClaimTypes.Email, "xxx@procodeguide.com"),
                    new Claim(JwtClaimTypes.Role, "admin"),
                    new Claim(JwtClaimTypes.WebSite, "https://www.etda.or.th")
                }
            }
        };
        }
    }
}
