﻿namespace IdsTemp.Models.Manage;

public class TwoFactorAuthenticationViewModel
{
    public bool HasAuthenticator { get; set; }

    public int RecoveryCodesLeft { get; set; }

    public bool Is2FaEnabled { get; set; }

    public bool IsMachineRemembered { get; set; }
    public string StatusMessage { get; set; }
}