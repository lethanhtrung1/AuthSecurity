namespace IdentityAuthentication.DTOs {
	public class AuthResponseDto {
		public bool IsSuccess { get; set; }
		public string? ErrorMessage { get; set; }
		//public string? AccessToken { get; set; }
		//public string? RefreshToken { get; set; }
		public bool Is2FactorRequired { get; set; }
		public string? Provider {  get; set; }
	}
}
