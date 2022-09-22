using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.AdminPanel;

public class UserModel
{
    public string Id { get; set; }
    [Required]
    public string UserName { get; set; }
    [Required]
    public string FirstName { get; set; }
    [Required]
    public string LastName { get; set; }
    [Required]
    public string Email { get; set; }
    public string Phone { get; set; }
    public string? Role { get; set; }
}