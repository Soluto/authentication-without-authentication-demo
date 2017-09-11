using System.Threading.Tasks;
using AuthorizationServer.Models;
using AuthorizationServer.Stores;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer.Controllers
{
    [Route("api/v1/application")]
    public class ApplicationController : Controller
    {
        private readonly IApplicationStore mStore;

        public ApplicationController(IApplicationStore store)
        {
            mStore = store;
        }
        [HttpPost]
        public async Task<IActionResult> Register([FromBody]ApplicationEntity entity)
        {
            await mStore.Add(entity.Id, entity.PublicKey, entity.OldSyncKey, entity.NewSyncKey);

            return Ok();
        }
    }
}