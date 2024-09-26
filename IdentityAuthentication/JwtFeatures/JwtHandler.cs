using IdentityAuthentication.DTOs;
using IdentityAuthentication.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityAuthentication.JwtFeatures {
	public class JwtHandler : IJwtHandler {
		private readonly IConfiguration _configuration;
		private readonly IConfigurationSection _jwtSettings;
		private readonly UserManager<User> _userManager;

		public JwtHandler(IConfiguration configuration, UserManager<User> userManager) {
			_configuration = configuration;
			_jwtSettings = _configuration.GetSection("JwtSettings");
			_userManager = userManager;
		}

		public async Task<TokenDto> CreateToken(User user, IList<string> roles, bool populateExp) {
			var signingCredentials = GetSigningCredentials();
			var claims = GetClaims(user, roles);
			var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

			var refreshToken = GenerateRefreshToken();

			user.RefreshToken = refreshToken;

			if (populateExp) {
				user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
			}

			await _userManager.UpdateAsync(user);

			var accessToken = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

			return new TokenDto(accessToken, refreshToken);
		}

		private SigningCredentials GetSigningCredentials() {
			var key = Encoding.UTF8.GetBytes(_jwtSettings["SecurityKey"]!);
			var secret = new SymmetricSecurityKey(key);

			return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
		}

		private List<Claim> GetClaims(User user, IList<string> roles) {
			var claims = new List<Claim>() {
				new Claim(ClaimTypes.Name, user.UserName!)
			};

			foreach (var role in roles) {
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			return claims;
		}

		private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims) {
			var tokenOptions = new JwtSecurityToken(
					issuer: _jwtSettings["Issuer"],
					audience: _jwtSettings["Audience"],
					claims: claims,
					expires: DateTime.Now.AddMinutes(Convert.ToDouble(_jwtSettings["ExpiryInMinutes"])),
					signingCredentials: signingCredentials
				);

			return tokenOptions;
		}

		private string GenerateRefreshToken() {
			var randomNumber = new byte[32];
			using (var rng = RandomNumberGenerator.Create()) {
				rng.GetBytes(randomNumber);

				return Convert.ToBase64String(randomNumber);
			}
		}

		private ClaimsPrincipal GetPrincipalFromExpiryToken(string token) {
			var jwtSettings = _configuration.GetSection("JwtSettings");
			var tokenValidationParameters = new TokenValidationParameters {
				ValidateAudience = true,
				ValidateIssuer = true,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["SecurityKey"]!)),
				ValidateLifetime = true,
				ValidAudience = jwtSettings["Audience"],
				ValidIssuer = jwtSettings["Issuer"]
			};

			var tokenHandler = new JwtSecurityTokenHandler();
			SecurityToken securityToken;
			var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
			var jwtSecurityToken = securityToken as JwtSecurityToken;

			if (jwtSecurityToken is null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase)) {
				throw new SecurityTokenException("Invalid Token");
			}

			return principal;
		}

		public async Task<TokenDto> RefreshToken(TokenDto tokenDto) {
			var principal = GetPrincipalFromExpiryToken(tokenDto.AccessToken);

			var user = await _userManager.FindByNameAsync(principal.Identity!.Name!);
			if (user is null || user.RefreshToken != tokenDto.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now) {
				throw new SecurityTokenException();
			}

			var roles = await _userManager.GetRolesAsync(user);

			return await CreateToken(user, roles, populateExp: false);
		}

		public void SetTokensInsideCookie(TokenDto tokenDto, HttpContext context) {
			context.Response.Cookies.Append("accessToken", tokenDto.AccessToken,
				new CookieOptions {
					Expires = DateTimeOffset.UtcNow.AddMinutes(5),
					HttpOnly = true,
					IsEssential = true,
					Secure = true,
					SameSite =SameSiteMode.None
				}
			);

			context.Response.Cookies.Append("refreshToken", tokenDto.RefreshToken,
				new CookieOptions {
					Expires = DateTimeOffset.UtcNow.AddDays(7),
					HttpOnly = true,
					IsEssential = true,
					Secure = true,
					SameSite = SameSiteMode.None
				}
			);
		}
	}
}
