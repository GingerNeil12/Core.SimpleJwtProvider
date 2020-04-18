using Microsoft.AspNetCore.Identity;
using System;

namespace SimpleJwtProvider.Models
{
    public class TokenIdentityUser : IdentityUser
    {
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }
    }
}
