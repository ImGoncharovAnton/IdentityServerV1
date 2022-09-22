namespace IdsTemp.Models.AdminPanel
{
    public class ClientViewModel
    {
        public IEnumerable<ClientSummaryModel> Clients { get; set; }
        public string? Filter { get; set; }
    }
}

