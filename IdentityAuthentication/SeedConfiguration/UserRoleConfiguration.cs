using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityAuthentication.SeedConfiguration {
	public class UserRoleConfiguration : IEntityTypeConfiguration<IdentityUserRole<string>> {
		public void Configure(EntityTypeBuilder<IdentityUserRole<string>> builder) {
			throw new NotImplementedException();
		}
	}
}
