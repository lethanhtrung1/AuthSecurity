using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAuthentication.Controllers {
	[Route("api/[controller]")]
	[ApiController]
	public class TestController : ControllerBase {
		[HttpGet]
		[Authorize(Policy = "OnlyAdminUsers")]
		public IActionResult TestAction() => Ok("Test message");
	}
}
