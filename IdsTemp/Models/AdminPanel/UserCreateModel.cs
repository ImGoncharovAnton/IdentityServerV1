using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdsTemp.Models.AdminPanel;

public class UserCreateModel: UserModel
{
    [Required]
    public string Password { get; set; }
    public IList<SelectListItem> RolesList { get; set; }
    public string SelectedRoleId { get; set; }
}