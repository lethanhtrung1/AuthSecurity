﻿using System.ComponentModel.DataAnnotations;

namespace IdentityAuthentication.DTOs {
	public class ForgotPasswordDto {
		[Required]
		[EmailAddress]
		public string? Email { get; set; }
		[Required]
		public string? ClientUri { get; set; }
	}
}
