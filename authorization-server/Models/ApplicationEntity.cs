using System;
using IdentityServer4.Models;

namespace AuthorizationServer.Models
{
    public class ApplicationEntity   
    {
        public string Id { get; set; }

        public JsonWebKey PublicKey { get; set; }

        public long OldSyncKey { get; set; }

        public long NewSyncKey { get; set; }

        public DateTime CreatedAt { get; set; }

        public DateTime UpdatedAt { get; set; }
    }
}