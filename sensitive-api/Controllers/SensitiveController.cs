using System;
using System.Collections.Generic;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace sensitive_api.Controllers
{
    [Route("api/v1/sensitive")]
    public class SensitiveController : Controller
    {
        private readonly Dictionary<string, string> deviceNickName;

        public SensitiveController()
        {
            deviceNickName = new Dictionary<string, string>();
            deviceNickName.Add("1", "Amazing device");
        }

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
            return Ok($"{deviceNickName[forDeviceId]}");
        }
    }
}