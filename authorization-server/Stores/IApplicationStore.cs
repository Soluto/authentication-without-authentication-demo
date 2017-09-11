using System.Threading.Tasks;
using IdentityServer4.Models;
using AuthorizationServer.Models;

namespace AuthorizationServer.Stores
{
    public interface IApplicationStore
    {
        Task<ApplicationEntity> Fetch(string appId);
        Task Revoke(string appId);
        Task Add(string appId, JsonWebKey publicKey, long oldSyncKey, long newSyncKey);
        Task UpdateState(string appId, long oldSyncKey, long newSyncKey);
    }
}