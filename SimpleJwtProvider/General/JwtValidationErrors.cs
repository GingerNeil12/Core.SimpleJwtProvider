namespace SimpleJwtProvider.General
{
    public class JwtValidationErrors
    {
        public const string USER_NOT_FOUND = "User account not found.";
        public const string REFRESH_TOKEN_ERROR = "Unable to add a Refresh Token to the User.";
        public const string CREDENTIALS_MISMATCH = "Supplied Credentials do not match.";
        public const string ACCOUNT_LOCKED = "User account locked.";
        public const string REFRESH_TOKEN_EXPIRED = "Refresh Token has Expired.";
        public const string DECODING_ERROR = "Error decoding provided Bearer Token.";
    }
}
