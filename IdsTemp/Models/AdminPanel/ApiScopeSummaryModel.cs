using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.AdminPanel;

public class ApiScopeSummaryModel
{
    [Required] 
    public string Name { get; set; }
    public string DisplayName { get; set; }
}