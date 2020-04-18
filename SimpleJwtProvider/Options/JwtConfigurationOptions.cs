namespace SimpleJwtProvider.Options
{
    public class JwtConfigurationOptions
    {
        // Issuer of the Token
        public string Issuer { get; }

        // Target Audience of the Token
        public string Audience { get; }

        // Secret Key for Signing the Token
        public string SecretKey { get; }

        public JwtConfigurationOptions(string issuer,
            string audience,
            string secretKey)
        {
            Issuer = issuer;
            Audience = audience;
            SecretKey = secretKey;
        }
    }
}
