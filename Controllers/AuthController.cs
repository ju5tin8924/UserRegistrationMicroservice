//using Microsoft.AspNetCore.Identity;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Text;
//using UserRegistrationMicroservice.Models;

//namespace UserRegistrationMicroservice.Controllers
//{
//    [Route("api/auth")]
//    [ApiController]
//    public class AuthController : ControllerBase
//    {
//        private readonly UserManager<ApplicationUser> _userManager;
//        private readonly IConfiguration _configuration;

//        public AuthController(UserManager<ApplicationUser> userManager, IConfiguration configuration)
//        {
//            _userManager = userManager;
//            _configuration = configuration;
//        }

//        // 🔹 1️⃣ Register New User
//        [HttpPost("register")]
//        public async Task<IActionResult> Register([FromBody] RegisterModel model)
//        {
//            if (!ModelState.IsValid)
//                return BadRequest(ModelState);

//            var existingUser = await _userManager.FindByEmailAsync(model.Email);
//            if (existingUser != null)
//                return BadRequest("User already exists");

//            var user = new ApplicationUser
//            {
//                UserName = model.Email,
//                Email = model.Email,
//                PhoneNumber = model.PhoneNumber
//            };

//            var result = await _userManager.CreateAsync(user, model.Password);
//            if (!result.Succeeded)
//                return BadRequest(result.Errors);

//            // Enable Two-Factor Authentication
//            await _userManager.SetTwoFactorEnabledAsync(user, true);

//            // Generate Authenticator Key
//            await _userManager.ResetAuthenticatorKeyAsync(user);
//            var key = await _userManager.GetAuthenticatorKeyAsync(user);

//            // Generate QR Code URI for authentication apps
//            var qrCodeUri = GenerateQrCodeUri(user.Email, key);

//            return Ok(new
//            {
//                message = "User registered successfully. Scan the QR code with your Authenticator App.",
//                authenticatorKey = key,
//                qrCodeUri
//            });
//        }




//        [HttpPost("login")]
//        public async Task<IActionResult> Login([FromBody] LoginModel model)
//        {
//            var user = await _userManager.FindByEmailAsync(model.Email);
//            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
//                return Unauthorized("Invalid credentials");

//            // Check if 2FA is enabled
//            if (await _userManager.GetTwoFactorEnabledAsync(user))
//            {
//                var key = await _userManager.GetAuthenticatorKeyAsync(user);
//                if (string.IsNullOrEmpty(key))
//                {
//                    return BadRequest("2FA is not set up for this user. Please enable it first.");
//                }

//                var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider);
//                if (string.IsNullOrEmpty(token))
//                {
//                    return BadRequest("Failed to generate 2FA token.");
//                }

//                return Ok(new { requires2FA = true, message = "2FA code required", token });
//            }

//            // Generate JWT Token for successful login
//            var authClaims = new List<Claim>
//    {
//        new Claim(ClaimTypes.Name, user.UserName),
//        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
//    };

//            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));

//            var jwtToken = new JwtSecurityToken(
//                issuer: _configuration["Jwt:Issuer"],
//                audience: _configuration["Jwt:Audience"],
//                expires: DateTime.UtcNow.AddHours(2),
//                claims: authClaims,
//                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
//            );

//            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(jwtToken), expiration = jwtToken.ValidTo });
//        }

//        private string GenerateQrCodeUri(string email, string key)
//        {
//            var issuer = "MyMicroserviceApp"; // Change this to your app name
//            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={key}&issuer={Uri.EscapeDataString(issuer)}";
//        }



//        //////

//        [HttpGet("enable-2fa")]
//        public async Task<IActionResult> EnableTwoFactorAuthentication()
//        {
//            var user = await _userManager.GetUserAsync(User);
//            if (user == null) return Unauthorized();

//            var key = await _userManager.GetAuthenticatorKeyAsync(user);
//            if (string.IsNullOrEmpty(key))
//            {
//                await _userManager.ResetAuthenticatorKeyAsync(user);
//                key = await _userManager.GetAuthenticatorKeyAsync(user);
//            }

//            var qrCodeUri = $"otpauth://totp/{_configuration["AppName"]}:{user.Email}?secret={key}&issuer={_configuration["AppName"]}";

//            return Ok(new { qrCodeUri, key });
//        }


//        ///// 

//        ///

//        [HttpPost("verify-2fa")]
//        public async Task<IActionResult> VerifyTwoFactor([FromBody] Verify2FAModel model)
//        {
//            var user = await _userManager.GetUserAsync(User);
//            if (user == null) return Unauthorized();

//            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, model.Code);

//            if (!isValid) return BadRequest("Invalid 2FA code");

//            return Ok("2FA Verification successful!");
//        }

//        public class Verify2FAModel
//        {
//            public string Code { get; set; }
//        }


//        ///



//    }

//    public class RegisterModel
//    {
//        public string Email { get; set; }
//        public string Password { get; set; }

//        public string PhoneNumber { get; set; }
//    }

//    public class LoginModel
//    {
//        public string Email { get; set; }
//        public string Password { get; set; }
//    }
//}


using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using UserRegistrationMicroservice.Models; // For email confirmation

namespace UserRegistrationMicroservice.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager; // Inject SignInManager
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
                IsTwoFactorEnabled = true // Enable 2FA by default
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            // Email Confirmation
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var confirmationUrl = $"https://yourfrontend.com/confirm-email?userId={user.Id}&token={encodedToken}"; // Replace with your frontend URL
            // TODO: Implement SendEmail(model.Email, confirmationUrl);

            // 2FA Setup (Generate Key and QR Code)
            await _userManager.ResetAuthenticatorKeyAsync(user); // Important: Reset before generating
            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            var qrCodeUri = GenerateQrCodeUri(user.Email, key);

            return Ok(new
            {
                message = "User registered successfully. Confirm your email and scan the QR code.",
                authenticatorKey = key,
                qrCodeUri
            });
        }

        //[HttpPost("login")]
        //public async Task<IActionResult> Login([FromBody] LoginModel model)
        //{
        //    var user = await _userManager.FindByEmailAsync(model.Email);
        //    //if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
        //    //{

        //    if (user == null || !await _userManager.VerifyTwoFactorTokenAsync(user, model.Password,model.Code))
        //    {
        //        return Unauthorized("Invalid credentials");
        //    }

        //    if (user.IsTwoFactorEnabled)
        //    {
        //        return Ok(new { requires2FA = true, message = "2FA code required" });
        //    }

        //    return GenerateJwtToken(user); // Generate JWT if 2FA is not enabled
        //}

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Unauthorized("Invalid credentials");
            }

            // Check password if 2FA is not enabled or no code is provided
            if (!user.IsTwoFactorEnabled || string.IsNullOrEmpty(model.Code))
            {
                if (!await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    return Unauthorized("Invalid credentials");
                }
            }
            else
            {
                // Verify 2FA code if provided
                var isValid2FA = await _userManager.VerifyTwoFactorTokenAsync(
                    user,
                    TokenOptions.DefaultAuthenticatorProvider,
                    model.Code
                );

                if (!isValid2FA)
                {
                    return BadRequest("Invalid 2FA code");
                }
            }

            return GenerateJwtToken(user); // Generate JWT if 2FA is not enabled
        }




        [HttpPost("verify-2fa")]
        public async Task<IActionResult> VerifyTwoFactor([FromBody] Verify2FAModel model)
        {
            var user = await _userManager.GetUserAsync(User); // Try getting the user from the current JWT (if available)

            if (user == null && User.Identity.IsAuthenticated) //Check if the user is authenticated from username and password
            {
                user = await _userManager.FindByEmailAsync(User.Identity.Name); // Get user by email
                if (user == null) return Unauthorized();
            }
            else if (user == null) return Unauthorized(); //If user is not authenticated through both ways then return unauthorized

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, model.Code);

            if (!isValid)
            {
                return BadRequest("Invalid 2FA code");
            }

            return GenerateJwtToken(user); // Generate JWT after 2FA is verified
        }


        [HttpGet("enable-2fa")] // Make sure you have this endpoint to enable 2FA
        public async Task<IActionResult> EnableTwoFactorAuthentication()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            var key = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(key))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                key = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var qrCodeUri = GenerateQrCodeUri(user.Email, key);

            return Ok(new { qrCodeUri, key });
        }


        private string GenerateQrCodeUri(string email, string key)
        {
            var issuer = _configuration["AppName"]; // Get app name from config (appsettings.json)
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={key}&issuer={Uri.EscapeDataString(issuer)}";
        }

        private IActionResult GenerateJwtToken(ApplicationUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddHours(2), // Adjust as needed
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }
    }

    // Models (RegisterModel, LoginModel, Verify2FAModel) should be defined here or in a separate file.
}
