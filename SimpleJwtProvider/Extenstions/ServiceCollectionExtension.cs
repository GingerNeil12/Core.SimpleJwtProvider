using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using SimpleJwtProvider.Interfaces;
using SimpleJwtProvider.Options;
using SimpleJwtProvider.Services;
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SimpleJwtProvider.Extenstions
{
    public static class ServiceCollectionExtension
    {
        /// <summary>
        /// This method will set up the Authentication Scheme to JWT
        /// </summary>
        /// <param name="services">IServiceCollection</param>
        /// <param name="options">Confiuration Options for the JWT Token</param>
        public static void AddJwtAuthentication(this IServiceCollection services,
            JwtConfigurationOptions options)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, builder =>
                {
                    builder.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = options.Issuer,
                        ValidAudience = options.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(options.SecretKey))
                    };

                    builder.Events = new JwtBearerEvents()
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception is SecurityTokenExpiredException)
                            {
                                context.HttpContext.Response.Headers.Add("RefreshToken", "true");
                            }
                            return Task.CompletedTask;
                        }
                    };
                });
        }

        /// <summary>
        /// This method will set up the Authentication Scheme 
        /// To be JWT and will set the OnAuthentication and OnForbidden
        /// Events to be the responseBody object that is passed in
        /// </summary>
        /// <param name="services">IServiceCollection</param>
        /// <param name="options">Confiuration Options for the JWT Token</param>
        /// <param name="authenticationFailedResponse">Custom Response Body to be sent on either Authentication failed or Access Forbidden</param>
        public static void AddJwtAuthentication(this IServiceCollection services,
            JwtConfigurationOptions options, object authenticationFailedResponse)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, builder =>
                {
                    builder.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = options.Issuer,
                        ValidAudience = options.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(options.SecretKey))
                    };

                    builder.Events = new JwtBearerEvents()
                    {
                        OnAuthenticationFailed = context =>
                        {
                            var bodyData = ConvertModelForSending(authenticationFailedResponse);
                            if (context.Exception is SecurityTokenExpiredException)
                            {
                                context.Response.Headers.Add("RefreshToken", "true");
                            }
                            context.Response.ContentType = "application/json";
                            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                            context.Response.Body.WriteAsync(bodyData, 0, bodyData.Length);
                            return Task.CompletedTask;
                        }
                    };
                });
        }

        /// <summary>
        /// This method will set up the Authentication Scheme 
        /// To be JWT and will set the OnAuthentication and OnForbidden
        /// Events to be the responseBody object that is passed in
        /// </summary>
        /// <param name="services">IServiceCollection</param>
        /// <param name="options">Confiuration Options for the JWT Token</param>
        /// <param name="authenticationFailedResponse">Custom Response Body to be sent on Authentication failed</param>
        /// <param name="forbiddenResponse">Custom Response Body to be sent on Forbidden Code</param>
        public static void AddJwtAuthentication(this IServiceCollection services,
            JwtConfigurationOptions options, object authenticationFailedResponse, object forbiddenResponse)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, builder =>
                {
                    builder.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = options.Issuer,
                        ValidAudience = options.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(options.SecretKey))
                    };

                    builder.Events = new JwtBearerEvents()
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception is SecurityTokenExpiredException)
                            {
                                context.Response.Headers.Add("RefreshToken", "true");
                            }
                            var bodyData = ConvertModelForSending(authenticationFailedResponse);
                            context.Response.ContentType = "application/json";
                            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                            context.Response.Body.WriteAsync(bodyData, 0, bodyData.Length);
                            return Task.CompletedTask;
                        },
                        OnForbidden = context =>
                        {
                            var bodyData = ConvertModelForSending(forbiddenResponse);
                            context.Response.ContentType = "application/json";
                            context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                            context.Response.Body.WriteAsync(bodyData, 0, bodyData.Length);
                            return Task.CompletedTask;
                        }
                    };
                });
        }

        public static void AddDefaultJwtProvider(this IServiceCollection services)
        {
            services.AddTransient<IJwtTokenProvider, DefaultTokenProvider>();
        }

        private static byte[] ConvertModelForSending(object model)
        {
            var json = GetJsonOfModel(model);
            return Encoding.UTF8.GetBytes(json);
        }

        private static string GetJsonOfModel(object model)
        {
            return JsonConvert.SerializeObject(model);
        }
    }
}
