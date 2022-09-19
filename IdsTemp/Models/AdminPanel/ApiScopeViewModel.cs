namespace IdsTemp.Models.AdminPanel;

public class ApiScopeViewModel
{
    public IEnumerable<ApiScopeSummaryModel> ApiScopes { get; set; }
    public string? Filter { get; set; }
}