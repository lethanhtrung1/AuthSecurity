using AutoMapper;
using IdentityAuthentication.DTOs;
using IdentityAuthentication.Entities;

namespace IdentityAuthentication.MappingConfig {
	public class MappingProfile : Profile {
		public MappingProfile() {
			CreateMap<UserForRegistrationDto, User>()
				.ForMember(u =>
					u.UserName,
					opt => opt.MapFrom(x => x.Email));
		}
	}
}
