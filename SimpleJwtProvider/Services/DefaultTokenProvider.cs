using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SimpleJwtProvider.General;
using SimpleJwtProvider.Interfaces;
using SimpleJwtProvider.Models;
using SimpleJwtProvider.Options;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SimpleJwtProvider.Services
{
    internal class DefaultTokenProvider : IJwtTokenProvider
    {
        private readonly UserManager<TokenIdentityUser> _userManager;
        private readonly ILogger<DefaultTokenProvider> _logger;

        public DefaultTokenProvider(UserManager<TokenIdentityUser> userManager,
            ILogger<DefaultTokenProvider> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        public IEnumerable<string> TokenErrors { get; private set; }

        public async Task<string> GenerateSymmetricTokenAsync(string userId,
            JwtTokenOptions options)
        {
            _logger.LogInformation($"Generating Jwt Token for: {userId}");
            var errors = new List<string>();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                errors.Add(JwtValidationErrors.USER_NOT_FOUND);
            }

            var refreshTokenAdded = await AddRefreshTokenToUserAsync(user, options.RefreshTokenExpiryInMinutes);
            if (!refreshTokenAdded)
            {
                errors.Add(JwtValidationErrors.REFRESH_TOKEN_ERROR);
            }

            if (errors.Any())
            {
                TokenErrors = errors;
                var logMessage = $"Errors Generating Token for: {userId}. Errors:";
                foreach (var error in errors)
                {
                    logMessage += $" {error}";
                }
                _logger.LogError(logMessage);
                return string.Empty;
            }

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtTokenClaimTypes.REFRESH_TOKEN, user.RefreshToken)
            };

            if (options.AddEmailToToken)
            {
                claims.Add(new Claim(ClaimTypes.Email, user.Email));
            }

            if (options.AddUsernameToToken)
            {
                claims.Add(new Claim(JwtTokenClaimTypes.USERNAME, user.UserName));
            }

            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var securityKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(options.SecretKey));
            var credentials = new SigningCredentials(
                securityKey, SecurityAlgorithms.HmacSha256);

            var header = new JwtHeader(credentials);
            var payload = new JwtPayload(
                issuer: options.Issuer,
                audience: options.Audience,
                claims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddMinutes(options.TokenExpiryInMinutes),
                issuedAt: DateTime.Now);

            var token = new JwtSecurityToken(header, payload);

            _logger.LogInformation($"Jwt Token generated for: {userId}");
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<string> RefreshSymmetricSecurityTokenAsync(JwtRefreshTokenModel model,
            JwtTokenOptions options)
        {
            _logger.LogInformation($"Refreshing Jwt Token for: {model.UserId}");
            var errors = new List<string>();

            var userId = GetUserIdFromBearerToken(model.CurrentBearerToken);
            if (userId == string.Empty)
            {
                errors.Add(JwtValidationErrors.DECODING_ERROR);
            }
            if (!userId.Equals(model.UserId))
            {
                errors.Add(JwtValidationErrors.CREDENTIALS_MISMATCH);
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                errors.Add(JwtValidationErrors.USER_NOT_FOUND);
                _logger.LogError($"User not found: {userId}");
                TokenErrors = errors;
                return string.Empty;
            }
            if (await _userManager.IsLockedOutAsync(user))
            {
                errors.Add(JwtValidationErrors.ACCOUNT_LOCKED);
            }
            if (user.RefreshTokenExpiry < DateTime.Now)
            {
                errors.Add(JwtValidationErrors.REFRESH_TOKEN_EXPIRED);
            }
            if (!user.RefreshToken.Equals(model.RefreshToken))
            {
                errors.Add(JwtValidationErrors.CREDENTIALS_MISMATCH);
            }

            if (errors.Any())
            {
                TokenErrors = errors;
                var logMessage = $"Errors Refreshing Token for: {userId}. Errors:";
                foreach (var error in errors)
                {
                    logMessage += $" {error}";
                }
                _logger.LogError(logMessage);
                return string.Empty;
            }

            var token = await GenerateSymmetricTokenAsync(userId, options);

            _logger.LogInformation($"Jwt Token Refreshed for user: {userId}");
            return token;
        }

        private string GetUserIdFromBearerToken(string bearerToken)
        {
            try
            {
                var token = new JwtSecurityToken(bearerToken);
                var idClaim = token.Claims
                    .Where(x => x.Type.Equals(JwtTokenClaimTypes.REFRESH_TOKEN))
                    .FirstOrDefault();
                if (idClaim == null)
                {
                    return string.Empty;
                }
                return idClaim.Value;
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error decoding Current Bearer Token: {ex.Message} || {ex.StackTrace}");
                return string.Empty;
            }
        }

        private async Task<bool> AddRefreshTokenToUserAsync(TokenIdentityUser user,
            int expiryMinutes)
        {
            user.RefreshToken = GenerateRefreshToken();
            user.RefreshTokenExpiry = DateTime.Now.AddMinutes(expiryMinutes);
            var result = await _userManager.UpdateAsync(user);
            return result.Succeeded;
        }

        private string GenerateRefreshToken()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var result = new byte[32];
                rng.GetBytes(result);
                return Convert.ToBase64String(result);
            }
        }
    }
}
