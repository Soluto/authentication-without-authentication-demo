namespace AuthorizationServer.Models
{
    public class AuthenticationPayload
    {
        public long OldSyncKey { get; set; }

        public long NewSyncKey { get; set; }
    }
}