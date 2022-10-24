using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdsTemp.Models.AdminPanel;

public class SettingsViewModel
{
    public IList<SelectListItem> ThemesList { get; set; }
    public string SelectedThemeId { get; set; }
}