# How to use

In the StartUp class do the following:


	public void ConfigureServices(IServiceCollection services)
	{
		services.AddDbContext<YOUR DB CONTEXT>();

		services.AddIdentity<TokenIdentityUser, IdentityRole>()
			.AddEntityFrameworkStores<YOUR DB CONTEXT>()
			.AddDefaultTokenProviders();


		var jwtConfigurationOptions = new JwtConfigurationOptions(
			issuer: "YOUR ISSUER", 
			audience: "YOUR AUDIENCE", 
			secretKey: "YOUR SECRET KEY");

		services.AddJwtAuthentication(jwtConfigurationOptions);

		services.AddAuthorization();

		services.AddDefaultJwtProvider();

		// Other Stuff you want to add here
	}


When needing a token all you need to do is:

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
			if(result == string.empty)
			{
				var tokenErrors = _provider.TokenErrors;
			}
			else
			{
				return tokenResult;
			}
		}
	}

