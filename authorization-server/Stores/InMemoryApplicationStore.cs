using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthorizationServer.Models;
using IdentityServer4.Models;

namespace AuthorizationServer.Stores
{
    public class InMemoryApplicationStore : IApplicationStore
    {
        private readonly Dictionary<string, ApplicationEntity> mApplications = 
            new Dictionary<string, ApplicationEntity>();

        public Task Add(string appId, JsonWebKey publicKey, long oldSyncKey, long newSyncKey)
        {
            mApplications.Add(appId, new ApplicationEntity
            {
                Id = appId,
                OldSyncKey = oldSyncKey,
                NewSyncKey = newSyncKey,
                PublicKey = publicKey
            });

            return Task.CompletedTask;
        }

        public Task<ApplicationEntity> Fetch(string appId)
        {
            return Task.FromResult(mApplications[appId]);
        }

        public Task Revoke(string appId)
        {
            mApplications.Remove(appId);
            return Task.CompletedTask;
        }

        public Task UpdateState(string appId, long oldSyncKey, long newSyncKey)
        {
            var app = mApplications[appId];

            if (appId == null)
            {
                throw new ArgumentException("App not found");
            }

            app.OldSyncKey = oldSyncKey;
            app.NewSyncKey = newSyncKey;
            mApplications[appId] = app;

            return Task.CompletedTask;
        }
    }
}