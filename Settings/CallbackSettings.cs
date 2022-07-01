using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.Settings
{
    public class CallbackSettings : ICallbackSettings
    {
        public string Token_request { get; set; }
        public string Qrcode_request { get; set; }
        public string Domain_QrCode { get; set; }
        public string Check_Token_request { get; set; }

    }
    public interface ICallbackSettings
    {
        public string Token_request { get; set; }
        public string Qrcode_request { get; set; }
        public string Domain_QrCode { get; set; }
        public string Check_Token_request { get; set; }
    }
}
