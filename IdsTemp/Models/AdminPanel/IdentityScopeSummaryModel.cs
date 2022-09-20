using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.AdminPanel;

public class IdentityScopeSummaryModel
{
    [Required] 
    public string Name { get; set; }
    public string DisplayName { get; set; }
}