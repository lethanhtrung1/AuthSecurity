using Microsoft.AspNetCore.Identity;

namespace IdentityAuthentication.Entities {
	public class Role : IdentityRole {
		public string? Description { get; set; }
	}
}
