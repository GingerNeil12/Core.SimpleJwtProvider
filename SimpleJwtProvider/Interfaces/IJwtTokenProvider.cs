using SimpleJwtProvider.Models;
using SimpleJwtProvider.Options;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SimpleJwtProvider.Interfaces
{
    public interface IJwtTokenProvider
    {
        // Any Errors while Generating or Refreshing a token will be in here
        IEnumerable<string> TokenErrors { get; }

        /// <summary>
        /// Generates a JWT token with a Symmetric Security Key
        /// </summary>
        /// <param name="userId">User Id of the User in the DB</param>
        /// <param name="options">JwtTokenOptions for generating the Token</param>
        /// <returns>JWT Token or string.empty if there is any errors</returns>
        Task<string> GenerateSymmetricTokenAsync(string userId, JwtTokenOptions options);

        /// <summary>
        /// Validates that the User is entitled to a new JWT Token
        /// and then issues a new one
        /// </summary>
        /// <param name="model">JwtRefreshModel with required properties</param>
        /// <param name="options">JwtTokenOptions for generating the Token</param>
        /// <returns>JWT Token or string.empty if there is any errors</returns>
        Task<string> RefreshSymmetricSecurityTokenAsync(JwtRefreshTokenModel model, JwtTokenOptions options);

        /// <summary>
        /// Generates a JWT based on the claims that have been passed into it
        /// </summary>
        /// <param name="claims">Claims to encode into the token</param>
        /// <param name="options">JwtTokenOptions for generating the Token</param>
        /// <returns>JWT Token or string.empty if there is any errors</returns>
        string GenerateSymmetricTokenAsync(IEnumerable<Claim> claims, JwtTokenOptions options);

        /// <summary>
        /// Will decode a JWT to get the claims from it
        /// </summary>
        /// <param name="bearerToken">Bearer Token to be decoded</param>
        /// <returns>List of claims contained within the token</returns>
        IEnumerable<Claim> DecodeToken(string bearerToken);
    }
}
