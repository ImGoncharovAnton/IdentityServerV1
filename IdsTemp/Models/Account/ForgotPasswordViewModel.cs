using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.Account;

public class ForgotPasswordViewModel
{
    [Required]
    public LoginResolutionPolicy? Policy { get; set; }
    [EmailAddress]
    public string Email { get; set; }
    public string Username { get; set; }
}