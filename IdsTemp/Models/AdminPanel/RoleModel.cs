using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.AdminPanel;

public class RoleModel
{
    public string Id { get; set; }
    [Required]
    public string Name { get; set; }
}