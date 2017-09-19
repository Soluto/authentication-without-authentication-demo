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
using Microsoft.IdentityModel.Tokens;

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
                await AuthenticateUser(
                    context.Request.Raw["device-id"], 
                    context.Request.Raw["signature"]);
            }
            catch (ValidationFailedException)
            {
                context.Result = new GrantValidationResult(TokenRequestErrors.InvalidRequest);

                return;
            }
            catch (Exception e)
            {
                var exception = new Exception("Failed to validate device authentication details", e);
                throw exception;
            }

            context.Result = new GrantValidationResult(
                IdentityServerPrincipal.Create(
                    context.Request.Raw["device-id"], 
                    context.Request.Raw["device-id"]));
        }

        private async Task AuthenticateUser(string deviceId, string signature)
        {
            ValidateParameters(deviceId, signature);

            var application = await mApplicationStore.Fetch(deviceId);

            if (application == null)
            {
                throw new ValidationFailedException("Application does not exist");
            }

            AuthenticationPayload payload;

            try
            {
                var publicKey = RSA.Create(new RSAParameters{
                    Exponent = Base64UrlEncoder.DecodeBytes(application.PublicKey.e),
                    Modulus = Base64UrlEncoder.DecodeBytes(application.PublicKey.n)
                });

                payload = JWT.Decode<AuthenticationPayload>(
                    signature, 
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

        private static void ValidateParameters(string deviceId, string signature)
        {
            if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(signature))
            {
                throw new ValidationFailedException("User or password is null");
            }
        }

        private async Task ValidatePayload(
            AuthenticationPayload payload, ApplicationEntity application)
        {
            if (payload.OldSyncKey == application.NewSyncKey)
            {
                application.OldSyncKey = payload.OldSyncKey;
                application.NewSyncKey = payload.NewSyncKey;

                await mApplicationStore.UpdateState(application.Id, application.OldSyncKey,
                        application.NewSyncKey);
            }
            else if (payload.OldSyncKey == application.OldSyncKey && 
                payload.NewSyncKey == application.NewSyncKey)
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