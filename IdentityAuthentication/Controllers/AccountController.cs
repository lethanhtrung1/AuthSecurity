using AutoMapper;
using EmailService;
using IdentityAuthentication.DTOs;
using IdentityAuthentication.Entities;
using IdentityAuthentication.JwtFeatures;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityAuthentication.Controllers {
	[Route("api/[controller]")]
	[ApiController]
	public class AccountController : ControllerBase {
		private readonly UserManager<User> _userManager;
		private readonly IJwtHandler _jwtHandler;
		private readonly IEmailSender _emailSender;
		private readonly IMapper _mapper;

		public AccountController(UserManager<User> userManager, IJwtHandler jwtHandler, IEmailSender emailSender, IMapper mapper) {
			_userManager = userManager;
			_jwtHandler = jwtHandler;
			_emailSender = emailSender;
			_mapper = mapper;
		}

		[HttpPost("register")]
		public async Task<IActionResult> Register([FromBody] UserForRegistrationDto request) {
			if (request is null) {
				return BadRequest();
			}

			var user = _mapper.Map<User>(request);
			var result = await _userManager.CreateAsync(user, request.Password!);

			if (!result.Succeeded) {
				var errors = result.Errors.Select(e => e.Description);
				return BadRequest(new RegistrationResponseDto {
					IsSuccess = false,
					Errors = errors
				});
			}

			var _user = await _userManager.FindByEmailAsync(request.Email!);

			var token = await _userManager.GenerateEmailConfirmationTokenAsync(_user!);
			var param = new Dictionary<string, string?> {
				{ "token", token },
				{ "email", _user!.Email }
			};
			var callback = QueryHelpers.AddQueryString(request.ClientUri!, param);

			var message = new Message(_user!.Email!, "Email Confirmation Token", callback);

			// Send email confirmation
			_emailSender.SendEmail(message);

			// Add role for user
			await _userManager.AddToRoleAsync(_user!, "Visitor");

			// Set 2FA enable
			await _userManager.SetTwoFactorEnabledAsync(_user, true);

			return StatusCode(201);
		}

		[HttpPost("login")]
		public async Task<IActionResult> Login([FromBody] UserForAuthenticationDto request) {
			var user = await _userManager.FindByEmailAsync(request.Email!);

			if (user is null) return BadRequest("Invalid requestz");

			// Check if email is confirmed
			if (!await _userManager.IsEmailConfirmedAsync(user)) {
				return Unauthorized(new AuthResponseDto {
					IsSuccess = false,
					ErrorMessage = "Email is not confirmed."
				});
			}

			// Check if account is locked out
			if (await _userManager.IsLockedOutAsync(user)) {
				return Unauthorized(new AuthResponseDto {
					IsSuccess = false,
					ErrorMessage = "The account is locked out."
				});
			}

			// Check password is incorrect
			if (!await _userManager.CheckPasswordAsync(user, request.Password!)) {
				// Increase failed accesses
				await _userManager.AccessFailedAsync(user);

				if (await _userManager.IsLockedOutAsync(user)) {
					var content = $"Your account is locked out. If you want to reset the password, " +
						$"you can use the forgot password link on the login page.";

					var message = new Message(request.Email!, "Locked out account information", content);

					_emailSender.SendEmail(message);

					return Unauthorized(new AuthResponseDto {
						IsSuccess = false,
						ErrorMessage = "The account is locked out."
					});
				}

				return Unauthorized(new AuthResponseDto {
					IsSuccess = false,
					ErrorMessage = "Email or password is incorrect."
				});
			}

			if (await _userManager.GetTwoFactorEnabledAsync(user)) {
				return await GenerateOTPFor2Factor(user);
			}

			var roles = await _userManager.GetRolesAsync(user);

			// Generate token
			var token = await _jwtHandler.CreateToken(user, roles, populateExp: true);

			// Set token to inside cookie
			_jwtHandler.SetTokensInsideCookie(token, HttpContext);

			// Reset access failed
			await _userManager.ResetAccessFailedCountAsync(user);

			return Ok(new AuthResponseDto {
				IsSuccess = true,
				//AccessToken = token.AccessToken,
				//RefreshToken = token.RefreshToken,
			});
		}

		private async Task<IActionResult> GenerateOTPFor2Factor(User user) {
			var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);

			if (!providers.Contains("Email")) {
				return Unauthorized(new AuthResponseDto {
					ErrorMessage = "Invalid 2-Factor Provider"
				});
			}

			var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

			var message = new Message(user.Email!, "Authentication token", token);

			_emailSender.SendEmail(message);

			return Ok(new AuthResponseDto {
				Is2FactorRequired = true,
				Provider = "Email"
			});
		}

		[HttpGet("verify-account")]
		public async Task<IActionResult> EmailConfirmation([FromQuery] string email, [FromQuery] string token) {
			var user = await _userManager.FindByEmailAsync(email);
			if (user is null) return BadRequest("Invalid email confirmation request.");

			var confirmResult = await _userManager.ConfirmEmailAsync(user, token);
			if (!confirmResult.Succeeded) {
				return BadRequest("Invalid email confirmation request.");
			}

			return Ok();
		}

		[HttpPost("forgot-password")]
		public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto request) {
			if (!ModelState.IsValid) return BadRequest("Invalid request");

			var user = await _userManager.FindByEmailAsync(request.Email!);
			if (user is null) return BadRequest("Invalid request");

			var token = await _userManager.GeneratePasswordResetTokenAsync(user);
			var param = new Dictionary<string, string?> {
				{ "token", token },
				{ "email", user.Email }
			};

			var callback = QueryHelpers.AddQueryString(request.ClientUri!, param);

			var message = new Message(user.Email!, "Reset password token", callback);

			_emailSender.SendEmail(message);

			return Ok();
		}

		[HttpPost("reset-password")]
		public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto request) {
			if (!ModelState.IsValid)
				return BadRequest("Invalid payload");

			var user = await _userManager.FindByEmailAsync(request.Email!);
			if (user is null)
				return BadRequest("Invalid request");

			// reset password
			var result = await _userManager.ResetPasswordAsync(user, request.Token!, request.Password!);
			if (!result.Succeeded) {
				var errors = result.Errors.Select(x => x.Description);
				return BadRequest(new {
					Errors = errors
				});
			}

			// if account is locked out
			await _userManager.SetLockoutEndDateAsync(user, null);

			return Ok("Reset password successful");
		}

		[HttpPost("two-factor")]
		public async Task<IActionResult> TwoFactor([FromBody] TwoFactorDto request) {
			if (!ModelState.IsValid) return BadRequest("Invalid payload");

			var user = await _userManager.FindByEmailAsync(request.Email!);
			if (user is null) return BadRequest("Invalid payload");

			var validVerification = await _userManager.VerifyTwoFactorTokenAsync(user, request.Provider!, request.Token!);

			var roles = await _userManager.GetRolesAsync(user);

			// Generate token
			var token = await _jwtHandler.CreateToken(user, roles, populateExp: true);

			// Reset access failed
			await _userManager.ResetAccessFailedCountAsync(user);

			_jwtHandler.SetTokensInsideCookie(token, HttpContext);

			return Ok(new AuthResponseDto {
				IsSuccess = true,
				//AccessToken = token.AccessToken,
				//RefreshToken = token.RefreshToken,
			});
		}

		[HttpPost("refresh-token")]
		public async Task<IActionResult> RefreshToken([FromBody] TokenDto request) {
			var tokenDto = await _jwtHandler.RefreshToken(request);

			// Set token to inside cookie
			_jwtHandler.SetTokensInsideCookie(tokenDto, HttpContext);

			return Ok();
		}
	}
}
