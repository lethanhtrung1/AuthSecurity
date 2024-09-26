using IdentityAuthentication.DTOs;
using IdentityAuthentication.Entities;

namespace IdentityAuthentication.JwtFeatures {
	public interface IJwtHandler {
		Task<TokenDto> CreateToken(User user, IList<string> roles, bool populateExp);
		Task<TokenDto> RefreshToken(TokenDto tokenDto);
		void SetTokensInsideCookie(TokenDto tokenDto, HttpContext context);
	}
}
