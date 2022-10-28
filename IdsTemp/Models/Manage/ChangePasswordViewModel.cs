﻿using System.ComponentModel.DataAnnotations;

namespace IdsTemp.Models.Manage;

public class ChangePasswordViewModel
{
    [Required]
    [DataType(DataType.Password)]
    public string OldPassword { get; set; }
    
    [Required]
    [DataType(DataType.Password)]
    public string NewPassword { get; set; }
    
    [Required]
    [DataType(DataType.Password)]
    [Compare("NewPassword", ErrorMessage = "Passwords is not equaled")]
    public string ConfirmPassword { get; set; }
    
    public string StatusMessage { get; set; }
}