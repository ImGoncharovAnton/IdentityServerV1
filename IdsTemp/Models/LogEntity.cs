namespace IdsTemp.Models;

public class LogEntity
{
    public string message { get; set; }
    public string message_template { get; set; }
    public int level { get; set; }
    public DateTime timestamp { get; set; }
    public string exception { get; set; }
    // private string _log_event { get; set; }
}