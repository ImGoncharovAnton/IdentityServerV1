using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.Admin;

public class ApiScopeSummaryModel
{
    [Required]
    public string Name { get; set; }
    public string DisplayName { get; set; }
}