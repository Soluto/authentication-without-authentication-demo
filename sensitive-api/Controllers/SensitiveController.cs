using System;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace sensitive_api.Controllers
{
    [Route("api/v1/sensitive")]
    public class SensitiveController : Controller
    {
        [HttpGet("{forDeviceId}")]
        [Authorize(
            Roles = "sensitive.read"
            )]
        public IActionResult GetSensitiveData(string forDeviceId)
        {
            var deviceId = Request.HttpContext.User.FindFirst(claim => claim.Type == "sub");
            if (!string.Equals(deviceId.Value, forDeviceId))
            {
                return Unauthorized();
            }
            return Ok($"Hello device {deviceId.Value}, here some sensitive data just for you: {new Random().Next(600)}");
        }
    }
}