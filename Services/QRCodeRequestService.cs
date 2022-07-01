using Authentication.IdentityServer.Models;
using Microsoft.IdentityModel.Tokens;
using Authentication.IdentityServer.Settings;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;

namespace Authentication.IdentityServer.Services
{
    public class QRCodeRequestService
    {

        private static readonly string SUCCESS = "success";

        private readonly ILoggerFactory _loggerFactory;

        public QRCodeRequestService(ILoggerFactory loggerFactory)
        {
            loggerFactory =
               LoggerFactory.Create(builder =>
                   builder.AddSimpleConsole(options =>
                   {
                       options.IncludeScopes = true;
                       options.SingleLine = true;
                       options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss]: ";
                   }));
            this._loggerFactory = loggerFactory;
        }

        public QRCodeResp qrCodeAsync(string client_Id, string secret, string qr_req_url)
        {
            var _logger = _loggerFactory.CreateLogger<QRCodeRequestService>();

            QRCodeResp qr_resp;

            try
            {
                _logger.LogInformation("Curl to: " + qr_req_url);

                var auth = client_Id + ":" + secret;
                var authBytes = System.Text.Encoding.UTF8.GetBytes(auth);
                var base64_auth = System.Convert.ToBase64String(authBytes);
                var basic_auth = "Basic " + base64_auth;

                var client = new HttpClient();
                client.DefaultRequestHeaders.Add("Authorization", basic_auth);
                //client.DefaultRequestHeaders.Add("client_secret", secret);
                client.Timeout = TimeSpan.FromMinutes(1);
                var response = client.GetAsync(qr_req_url).Result;
                var result = response.Content.ReadAsStringAsync().Result;

                if (response.StatusCode.Equals(HttpStatusCode.OK))
                {
                    if (result.Contains(SUCCESS))
                    {
                        qr_resp = JsonConvert.DeserializeObject<QRCodeResp>(result);

                        if (String.IsNullOrEmpty(qr_resp.qrcode) || String.IsNullOrEmpty(qr_resp.qrToken))
                        {
                            _logger.LogError("Get Qr Code ERROR: " + qr_resp.description);
                            qr_resp = null;
                        }
                    }
                    else
                    {
                        var resp = JsonConvert.DeserializeObject<QRCodeResp>(result);
                        _logger.LogError("Get Qr Code Status ERROR: " + resp.result + ", Desc: " + resp.description);
                        qr_resp = null;
                    }
                }
                else
                {
                    var resp = JsonConvert.DeserializeObject<QRCodeResp>(result);
                    _logger.LogError("Get Qr Code ERROR: HTTP Status Code " + response.StatusCode + ", Desc: " + resp.description);
                    qr_resp = null;
                }
            }
            catch (Exception ex)
            {
                qr_resp = null;
                _logger.LogError("Get Qr Code ERROR: " + ex.Message);
                ex.StackTrace.ToString();
            }

            return qr_resp;
        }

        public bool qrCodeTokenAsync(string client_Id, string secret, string chk_qr_token_url)
        {
            var _logger = _loggerFactory.CreateLogger<QRCodeRequestService>();

            //QRCodeResp qr_resp;

            try
            {
                _logger.LogInformation("Curl to: " + chk_qr_token_url);

                var auth = client_Id + ":" + secret;
                var authBytes = System.Text.Encoding.UTF8.GetBytes(auth);
                var base64_auth = System.Convert.ToBase64String(authBytes);
                var basic_auth = "Basic " + base64_auth;

                var client = new HttpClient();
                client.DefaultRequestHeaders.Add("Authorization", basic_auth);
                //client.DefaultRequestHeaders.Add("client_secret", secret);
                client.Timeout = TimeSpan.FromMinutes(1);
                var response = client.GetAsync(chk_qr_token_url).Result;
                var result = response.Content.ReadAsStringAsync().Result;

                if (response.StatusCode.Equals(HttpStatusCode.OK))
                {
                    if (result.Contains("used"))
                    {
                        _logger.LogInformation("Check Qr Token OK");
                        return true;
                    }
                    else
                    {
                        _logger.LogError("Check Qr Token Failed");
                        return false;
                    }
                }
                else
                {
                    _logger.LogError("Check Qr Token ERROR: HTTP Status Code " + response.StatusCode + ", Desc: " + response.Content);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Check Qr Token Exeption: " + ex.Message);
                ex.StackTrace.ToString();
                return false;
            }

            //return qr_resp;
        }
    }
}
