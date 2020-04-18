namespace SimpleJwtProvider.Models
{
    public class JwtRefreshTokenModel
    {
        // User Id of the User in the DB
        public string UserId { get; }

        // Provided Refresh Token of the User
        public string RefreshToken { get; }

        // Current Bearer Token provided to the User
        public string CurrentBearerToken { get; }

        public JwtRefreshTokenModel(string userId,
            string refreshToken,
            string currentBearerToken)
        {
            UserId = userId;
            RefreshToken = refreshToken;
            CurrentBearerToken = currentBearerToken;
        }
    }
}
