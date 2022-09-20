namespace IdsTemp.Models.AdminPanel;

public class UsersViewModel
{
    public IEnumerable<UserModel> Users { get; set; }
    public string? Filter { get; set; }
}