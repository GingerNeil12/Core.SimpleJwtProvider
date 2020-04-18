namespace SimpleJwtProvider.Options
{
    public class JwtTokenOptions
    {
        // Issuer of the Token
        public string Issuer { get; }

        // Target Audience of the Token
        public string Audience { get; }

        // Secret Key for Signing the Token
        public string SecretKey { get; }

        // Expiry time of the Token in Minutes
        public int TokenExpiryInMinutes { get; }

        // Expiry time of the Refresh Token in Minutes
        public int RefreshTokenExpiryInMinutes { get; }

        // Whether to add the users Email to the Token Claims
        public bool AddEmailToToken { get; }

        // Whether to add the users Username to the Token Claims
        public bool AddUsernameToToken { get; }

        public JwtTokenOptions(string issuer,
            string audience,
            string secretKey,
            int tokenExpiryInMinutes,
            int refreshTokenExpiryInMinutes,
            bool addEmailToToken,
            bool addUsernameToToken)
        {
            Issuer = issuer;
            Audience = audience;
            SecretKey = secretKey;
            TokenExpiryInMinutes = tokenExpiryInMinutes;
            RefreshTokenExpiryInMinutes = refreshTokenExpiryInMinutes;
            AddEmailToToken = addEmailToToken;
            AddUsernameToToken = addUsernameToToken;
        }
    }
}
