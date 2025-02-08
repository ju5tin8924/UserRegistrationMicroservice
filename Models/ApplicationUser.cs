using Microsoft.AspNetCore.Identity;

namespace UserRegistrationMicroservice.Models
{
    public class ApplicationUser:IdentityUser
    {
        //public string FullName { get; set; }
        public bool IsTwoFactorEnabled { get; set; } = true;
    }
}
