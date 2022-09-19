using IdsTemp.Models.Consent;

namespace IdsTemp.Models.Device
{
    public class DeviceAuthorizationInputModel : ConsentInputModel
    {
        public string UserCode { get; set; }
    }
}