using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.Settings
{
    public class QRSettings : IQRSettings
    {
        public string Client_Id { get; set; }
        public string Secret { get; set; }
    }
    public interface IQRSettings
    {
        public string Client_Id { get; set; }
        public string Secret { get; set; }
    }
}
