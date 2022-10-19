using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models;

public class Unit
{
    public int Id { get; set; }
    
    [Required]
    [StringLength(25)]
    public string Name { get; set; }
    
    [Required]
    [StringLength(75)]
    public string Description { get; set; }
}

public enum SortOrder { Ascending = 0, Descending = 1}