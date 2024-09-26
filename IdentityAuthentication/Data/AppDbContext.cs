using IdentityAuthentication.Entities;
using IdentityAuthentication.SeedConfiguration;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityAuthentication.Data {
	public class AppDbContext : IdentityDbContext<User, Role, string> {
		public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

		protected override void OnModelCreating(ModelBuilder builder) {
			base.OnModelCreating(builder);

			builder.ApplyConfiguration(new RoleConfiguration());
			//builder.ApplyConfiguration(new UserRoleConfiguration());
		}
	}
}
