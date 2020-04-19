# How to use

This section will cover how to add the middleware to the StartUp DI.

You must also make sure of the following:

* Your application user must inherit TokenIdentityUser which itself inherits IdentityUser
* Your application Db Context must inherit from IdentityDbContext<T> with the TokenIdentityUser being the T 

In the StartUp class do the following:


	public void ConfigureServices(IServiceCollection services)
	{
		// Add your Db Context
		services.AddDbContext<YOUR DB CONTEXT>();

		// Configure the UserManager and RoleManager
		services.AddIdentity<TokenIdentityUser, IdentityRole>()
			.AddEntityFrameworkStores<YOUR DB CONTEXT>()
			.AddDefaultTokenProviders();


		var jwtConfigurationOptions = new JwtConfigurationOptions(
			issuer: "YOUR ISSUER", 
			audience: "YOUR AUDIENCE", 
			secretKey: "YOUR SECRET KEY");

		// For using the standard response body
		services.AddJwtAuthentication(jwtConfigurationOptions);

		// For overriding the response body for OnAuthentication Failed
		services.AddJwtAuthentication(jwtConfigurationOptions, YourUnauthorizedResponseModel);

		// For overriding the response body for both the OnAuthentication Failed and Forbidden
		services.AddJwtAuthentication(jwtConfigurationOptions, YourUnauthorizedResponseModel, YourForbiddenResponseModel);

		services.AddAuthorization();

		services.AddDefaultJwtProvider();

		// Other Stuff you want to add here
	}

# How to Generate a Token

In your class you just need to add the following to generate a token. The GenerateSymmetricTokenAsync method 
takes in the userId that the token is for as well as some options that need to be filled out. 
The method will then generate the token and add a refresh token to the users table.
If there is any errors when creating a token the emthod will return a string.empty. The errors are then able to be 
found in a handy error list of the class called TokenErrors. Also logging is set up so if you have any logging middleware 
set up the default token provider will have an ILogger injected and will output to your logger of choice.

	public class Foo
	{
		private readonly IJwtTokenProvider _provider;

		public Foo(IJwtTokenProvider provider)
		{
			_provider = provider;
		}

		public async Task<string> GetTokenForUser(string userId)
		{
			var options = new JwtTokenOptions(
				issuer: "YOUR ISSUER",
				audience: "YOUR AUDIENCE",
				secretKey: "YOUR SECRET KEY",
				tokenExpiryInMinutes: 0,
				refreshTokenExpiryInMinutes: 0,
				addEmailToToken: true,
				addUsernameToToken: true);

			var tokenResult = await _provider.GenerateSymmetricTokenAsync(userId, options);
			
			// There has been an error
			if(result == string.empty)
			{
				// Get the errors and do something with them
				var tokenErrors = _provider.TokenErrors;
			}
			else
			{
				return tokenResult;
			}
		}
	}

# Refresh Token

When a token needs to be refreshed due to it being Expired, the response will be a 401 Unauthorized. Contained 
within the Header of the Response will be a Key Value pair of "RefreshToken" and "true". If this does not exist in the 
response Header then it is a normal Unauthorized Response. 

Like with the above section it requires some options to be input as well as a specific model. This model will contain:

* User Id
* Refresh Token
* Current Bearer Token

These are used internally to the default token provider to verify that the token being refreshed should be against that user. 
It will also check to see if the User has been set to locked out as well. 

Like the previous section the refresh token method will return an string.empty if there is any errors and will set the
TokenErrors property to the list of errors found. Also like the previous section, there is logging enabled.

	public class Foo
	{
		private readonly IJwtTokenProvider _provider;

		public Foo(IJwtTokenProvider provider)
		{
			_provider = provider;
		}

		public async Task<string> GetRefreshTokenForUser(string userId, string refreshToken, string currentBearerToken)
		{
			var refreshTokenModel = new JwtRefreshTokenModel(
				userId: userId, // User Id of the user in the DB
				refreshToken: refreshToken, // Refresh Token previously issued
				currentBearerToken: currentBearerToken" // Current Bearer Token previously issued
			);

			var options = new JwtTokenOptions(
				issuer: "YOUR ISSUER",
				audience: "YOUR AUDIENCE",
				secretKey: "YOUR SECRET KEY",
				tokenExpiryInMinutes: 0,
				refreshTokenExpiryInMinutes: 0,
				addEmailToToken: true,
				addUsernameToToken: true);

			var tokenResult = await _provider.RefreshSymmetricSecurityTokenAsync(refreshTokenModel, options);
			
			// There has been an error
			if(tokenResult == string.empty)
			{
				// Get the errors and do something with them
				var errors = _provider.TokenErrors;
				return string.empty;
			}
			else
			{
				return tokenResult;
			}
		}
	}