using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdsTemp.Models.AdminPanel;

public class UserEditModel: UserModel
{
    public IList<SelectListItem> RolesList { get; set; }
    public string SelectedRoleId { get; set; }
}