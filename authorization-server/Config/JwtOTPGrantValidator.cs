using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using AuthorizationServer.Models;
using AuthorizationServer.Stores;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Jose;

namespace AuthorizationServer.Config
{
    public class JwtOTPGrantValidator : IExtensionGrantValidator
    {
        private class ValidationFailedException : Exception
        {
            public ValidationFailedException(string message) : base(message)
            {
                
            }

            public ValidationFailedException(string message, Exception innerException)
                : base(message, innerException)
            {
                
            }
        }

        private readonly IApplicationStore mApplicationStore;

        public JwtOTPGrantValidator(IApplicationStore store)
        {
            this.mApplicationStore = store;
        }

        public string GrantType => "jwt-otp";

        public async Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            try
            {
                await AuthenticateUser(context.Request.Raw["app-id"], context.Request.Raw["jwt"]);
            }
            catch (ValidationFailedException e)
            {
                /* 
                mLogger.Error()
                    .Message("Token validation failed")
                    .WithRoleEnvironmentValues()
                    .Property("DeviceId", context.UserName)
                    .ExceptionOnlyIfNotNull(e)
                    .Write();

                */

                context.Result = new GrantValidationResult(TokenRequestErrors.InvalidRequest);

                return;
            }
            catch (Exception e)
            {
                var exception = new Exception("Failed to validate device authentication details", e);
                throw exception;
            }

            /* 

            mLogger.Info()
                .Message("Token validation succeded")
                .WithRoleEnvironmentValues()
                .Property("DeviceId", context.UserName)
                .Write();
            */
            
            context.Result = new GrantValidationResult(IdentityServerPrincipal.Create(context.Request.Raw["app-id"], context.Request.Raw["app-id"]));
        }

        private async Task AuthenticateUser(string userName, string password)
        {
            ValidateParameters(userName, password);

            var application = await mApplicationStore.Fetch(userName);

            if (application == null)
            {
                throw new ValidationFailedException("Application does not exist");
            }

            AuthenticationPayload payload;

            try
            {
                /* 
                var headers = JWT.Headers(password);
                var log = mLogger.Info().Message("Validating signature")
                    .WithRoleEnvironmentValues()
                    .Property("DeviceId", application.Id);*/

                var publicKey = RSA.Create(new RSAParameters{
                    Exponent = Convert.FromBase64String(application.PublicKey.e),
                    Modulus = Convert.FromBase64String(application.PublicKey.n)
                });

                payload = JWT.Decode<AuthenticationPayload>(
                    password, 
                    publicKey);
            }
            catch (Exception e)
            {
                throw new ValidationFailedException("Signature validation failed", e);
            }

            if (payload == null)
            {
                throw new ValidationFailedException("Payload is null");
            }
            
            await ValidatePayload(payload, application);
        }

        private static void ValidateParameters(string userName, string password)
        {
            Guid dummy;

            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(password) || !Guid.TryParse(userName, out dummy))
            {
                throw new ValidationFailedException("User or password is null");
            }
        }

        private async Task ValidatePayload(AuthenticationPayload payload, ApplicationEntity application)
        {
            /* 
            mLogger.Info()
                .Message("Validating payload")
                .WithRoleEnvironmentValues()
                .Property("DeviceId", application.Id)
                .Property("ServerOldSyncKey", application.OldSyncKey)
                .Property("ServerNewSyncKey", application.NewSyncKey)
                .Property("ClientOldSyncKey", payload.OldSyncKey)
                .Property("ClientNewSyncKey", payload.NewSyncKey)
                .Write();*/
            
            if (payload.OldSyncKey == application.NewSyncKey)
            {
                application.OldSyncKey = payload.OldSyncKey;
                application.NewSyncKey = payload.NewSyncKey;

                await mApplicationStore.UpdateState(application.Id, application.OldSyncKey,
                        application.NewSyncKey);
            }
            else if (payload.OldSyncKey == application.OldSyncKey && payload.NewSyncKey == application.NewSyncKey)
            {
                throw new ValidationFailedException("Payload invalid - equal to stored payload");
            }
            else
            {
                await mApplicationStore.Revoke(application.Id);
                throw new ValidationFailedException("Payload is invalid, application revoked");
            }
        }
    }
}