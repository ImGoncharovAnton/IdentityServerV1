using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdsTemp.Models.Account
{
    public class RedirectViewModel: PageModel
    {
        public string RedirectUri { get; set; }

        public IActionResult OnGet(string redirectUri)
        {
            if (!Url.IsLocalUrl(redirectUri))
            {
                return RedirectToPage("~/Error");
            }

            RedirectUri = redirectUri;
            return Page();
        }
    }
}