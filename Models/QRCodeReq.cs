using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.Models
{
    public class QRCodeReq
    {
        public string client_id { get; set; }
        public string client_secret { get; set; }
    }
}
