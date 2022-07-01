using Authentication.IdentityServer.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace Authentication.IdentityServer.Services
{
    public class CheckBasicAuthenService
    {
        private static readonly string SUCCESS = "success";

        private readonly ILoggerFactory _loggerFactory;

        public CheckBasicAuthenService(ILoggerFactory loggerFactory)
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

        public bool checkBasicAuthStatus(string client_Id, string secret, string username, string checkBasicAuth_URL)
        {
            var _logger = _loggerFactory.CreateLogger<CheckBasicAuthenService>();

            CheckBasicAuthResp chk_resp = new CheckBasicAuthResp();

            try
            {

                _logger.LogInformation("---------- Start CheckBasicAuthStatus Session() ----------");

                _logger.LogInformation("Username: " + username);

                _logger.LogInformation("Curl to: " + checkBasicAuth_URL);

                var auth = client_Id + ":" + secret;
                var authBytes = System.Text.Encoding.UTF8.GetBytes(auth);
                var base64_auth = System.Convert.ToBase64String(authBytes);
                var basic_auth = "Basic " + base64_auth;

                var chk_req_body = new CheckBasicAuthReq();
                chk_req_body.username = username;

                var client = new HttpClient();
                client.DefaultRequestHeaders.Add("Authorization", basic_auth);
                //client.DefaultRequestHeaders.Add("Authorization", "TOKEN");
                client.Timeout = TimeSpan.FromMinutes(1);
                var response = client.PostAsJsonAsync(checkBasicAuth_URL, chk_req_body).Result;

                if (response.StatusCode.Equals(HttpStatusCode.OK))
                {
                    var result = response.Content.ReadAsStringAsync().Result;
                    chk_resp = JsonConvert.DeserializeObject<CheckBasicAuthResp>(result);
                    var unixNow = DateTimeOffset.Now.ToUnixTimeSeconds();
                    _logger.LogInformation("Unix time Now: " + unixNow);

                    if (chk_resp.status.Equals(SUCCESS) && chk_resp.allow_basic_auth.Equals("Y") && unixNow < chk_resp.allow_expire_unix)
                    {
                        _logger.LogInformation("Check Basic Authen OK: " + chk_resp.description);
                        return true;
                    }
                    else
                    {
                        _logger.LogError("Check Basic Authen Failed -> status: " + chk_resp.status+", desc: "+ chk_resp.description+", basic_authen_status: "+ chk_resp.allow_basic_auth + ", basic_authen_expire: " + chk_resp.allow_expire_unix);
                        return false;
                    }
                }
                else
                {
                    var result_error = response.Content.ReadAsStringAsync().Result;
                    chk_resp = JsonConvert.DeserializeObject<CheckBasicAuthResp>(result_error);

                    chk_resp.status = "error";
                    chk_resp.description = chk_resp.description;
                    _logger.LogError("Check Basic Authen Failed: " + response.StatusCode);

                    return false;
                }
            }
            catch (Exception ex)
            {
                chk_resp.status = "error";
                chk_resp.description = ex.Message.ToString();
                _logger.LogError("Check Basic Authen Exception: " + ex.Message.ToString());
                ex.StackTrace.ToString();

                return false;
            }
            finally
            {
                _logger.LogInformation("---------- End CheckBasicAuthStatus Session() ----------");
            }
        }
    }
}
