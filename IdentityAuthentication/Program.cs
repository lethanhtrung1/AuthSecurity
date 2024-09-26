using EmailService;
using IdentityAuthentication.Common;
using IdentityAuthentication.Data;
using IdentityAuthentication.Entities;
using IdentityAuthentication.JwtFeatures;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => {
	options.AddSecurityDefinition(name: JwtBearerDefaults.AuthenticationScheme, securityScheme: new OpenApiSecurityScheme {
		Name = "Authorization",
		Description = "Enter the Bear Authorization string as following: `Bearer Generated-JWT-Token`",
		In = ParameterLocation.Header,
		Type = SecuritySchemeType.ApiKey,
		Scheme = "Bearer"
	});
	options.AddSecurityRequirement(new OpenApiSecurityRequirement {
		{
			new OpenApiSecurityScheme {
				Reference = new OpenApiReference {
					Type = ReferenceType.SecurityScheme,
					Id = JwtBearerDefaults.AuthenticationScheme
				}
			},
			new List<string>()
		}
	});
});

builder.Services.AddDbContext<AppDbContext>(options => {
	options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddAuthentication(options => {
	options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
	options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
	options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options => {
	var jwtSettings = builder.Configuration.GetSection("JwtSettings");
	options.TokenValidationParameters = new TokenValidationParameters {
		ValidateAudience = true,
		ValidateIssuer = true,
		ValidateLifetime = true,
		ValidateIssuerSigningKey = true,
		ValidIssuer = jwtSettings["Issuer"],
		ValidAudience = jwtSettings["Audience"],
		IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.GetSection("SecurityKey").Value!))
	};

	// Use HttpOnly Cookie
	options.Events = new JwtBearerEvents {
		OnMessageReceived = ctx => {
			ctx.Request.Cookies.TryGetValue("accessToken", out var accessToken);
			if (!string.IsNullOrEmpty(accessToken)) {
				ctx.Token = accessToken;
			}
			return Task.CompletedTask;
		}
	};
});

builder.Services.AddIdentity<User, Role>(options => {
	options.SignIn.RequireConfirmedEmail = true;
	options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider;

	// Reset password
	options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider;

	// 2FA
	options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultEmailProvider;

	options.Password.RequiredLength = 8;
	options.Password.RequireDigit = true;
	options.Password.RequireLowercase = true;
	options.Password.RequireUppercase = true;
	options.Password.RequireNonAlphanumeric = true;

	// Lockout
	options.Lockout.AllowedForNewUsers = true;
	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
	options.Lockout.MaxFailedAccessAttempts = 3;
})
	.AddEntityFrameworkStores<AppDbContext>()
	.AddDefaultTokenProviders()
	.AddPasswordValidator<CustomPasswordValidator<User>>();

builder.Services.Configure<DataProtectionTokenProviderOptions>(options => {
	options.TokenLifespan = TimeSpan.FromHours(1);
});

//builder.Services.AddSingleton<JwtHandler>();

var emailConfig = builder.Configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
builder.Services.AddSingleton(emailConfig!);
builder.Services.AddScoped<IEmailSender, EmailSender>();

builder.Services.AddScoped<IJwtHandler, JwtHandler>();

builder.Services.AddAuthorization(options => {
	options.AddPolicy(
		"OnlyAdminUsers",
		policy => policy.RequireRole("Admin")
	);
});

builder.Services.AddAutoMapper(typeof(Program).Assembly);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
