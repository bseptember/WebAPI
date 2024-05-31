namespace WebAPI.Models
{
    public class AuthLoginParameters
    {
        public string? uri { get; set; }
        public string? challenge { get; set; }
    }

    public class AuthAccessTokenParameters
    {
        public string? uri { get; set; }
        public string? code { get; set; }
        public string? verifier { get; set; }
    }
    public class AuthLogoutParameters
    {
        public string? uri { get; set; }
    }

    public class TokenParameters
    {
        public string? access_token { get; set; }
        public long expires_in { get; set; }
        public string? id_token { get; set; }
        public string? refresh_token { get; set; }
        public long refresh_expires_in { get; set; }
        public string? token_type { get; set; }
        public string? userId { get; set; }
        public string? session_state { get; set; }
        public string? scope { get; set; }

    }
}
