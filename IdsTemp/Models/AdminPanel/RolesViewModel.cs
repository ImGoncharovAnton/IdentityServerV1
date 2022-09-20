using Microsoft.AspNetCore.Identity;

namespace IdsTemp.Models.AdminPanel;

public class RolesViewModel
{
    public ICollection<RoleModel> Roles { get; set; }
    public string? Filter { get; set; }
}