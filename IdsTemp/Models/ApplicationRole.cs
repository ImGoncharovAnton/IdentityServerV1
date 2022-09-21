using Microsoft.AspNetCore.Identity;

namespace IdsTemp.Models;

public class ApplicationRole: IdentityRole<string>
{
    public ApplicationRole()
    {
        Id = Guid.NewGuid().ToString();
    }

    public ApplicationRole(string roleName): this()
    {
        Name = roleName;
    }
    
    public DateTime CreateDate { get; set; } = DateTime.UtcNow;
    public ICollection<ApplicationUserRole> UserRoles { get; set; }
}