// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


using IdsTemp.MainModule.Consent;

namespace IdsTemp.MainModule.Device
{
    public class DeviceAuthorizationInputModel : ConsentInputModel
    {
        public string UserCode { get; set; }
    }
}