using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.Models
{
    public class QRCodeResp
    {
        [Required]
        public string qrToken { get; set; }
        [Required]
        public string qrcode { get; set; }
        public string result { get; set; }
        public string description { get; set; }
    }
}
