using IdentityAuthentication.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityAuthentication.SeedConfiguration {
	public class RoleConfiguration : IEntityTypeConfiguration<Role> {
		public void Configure(EntityTypeBuilder<Role> builder) {
			builder.HasData(
				new Role {
					Id = "dc6b95ea-3a61-49cf-83fc-74cdb16df1c9",
					Name = "Visitor",
					NormalizedName = "VISITOR",
					Description = "The visitor role for the user"
				},
				new Role {
					Id = "afc8272c-8a66-43f7-bd79-0a42ee6a4bb4",
					Name = "Admin",
					NormalizedName = "ADMIN",
					Description = "The admin role for the user"
				}
			);
		}
	}
}
