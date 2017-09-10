using System.Collections.Generic;
using IdentityServer4.Models;

namespace AuthorizationServer.Config
{
    public static class Resources
    {
        public static IEnumerable<ApiResource> Get() => new List<ApiResource>
            {
                new ApiResource("api1", "My API")
            };

    }
}