namespace IdsTemp.Models.AdminPanel
{
    public class IdentityScopeViewModel
    {
        public IEnumerable<IdentityScopeSummaryModel> Scopes { get; set; }
        public string? Filter { get; set; }
    }
}
