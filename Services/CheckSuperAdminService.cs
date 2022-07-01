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
    public class CheckSuperAdminService
    {
        private static readonly string SUCCESS = "success";

        private readonly ILoggerFactory _loggerFactory;

        public CheckSuperAdminService(ILoggerFactory loggerFactory)
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

        public bool checkSuperAdmin(string apikey, string username, string password, string checkSuperAdmin_URL)
        {
            var _logger = _loggerFactory.CreateLogger<CheckSuperAdminService>();

            CheckSuperAdminResp sup_resp = new CheckSuperAdminResp();

            try
            {

                _logger.LogInformation("---------- Start CheckSuperAdmin Session() ----------");

                _logger.LogInformation("Username: " + username);

                _logger.LogInformation("Curl to: " + checkSuperAdmin_URL);

                var sup_req_body = new CheckSuperAdminReq();
                sup_req_body.username = username;
                sup_req_body.password = password;

                var client = new HttpClient();
                client.DefaultRequestHeaders.Add("apikey", apikey);
                //client.DefaultRequestHeaders.Add("Authorization", "TOKEN");
                client.Timeout = TimeSpan.FromMinutes(1);
                var response = client.PostAsJsonAsync(checkSuperAdmin_URL, sup_req_body).Result;

                if (response.StatusCode.Equals(HttpStatusCode.OK))
                {
                    var result = response.Content.ReadAsStringAsync().Result;
                    sup_resp = JsonConvert.DeserializeObject<CheckSuperAdminResp>(result);
                    var unixNow = DateTimeOffset.Now.ToUnixTimeSeconds();

                    if (sup_resp.result.Equals(SUCCESS))
                    {
                        _logger.LogInformation("Check Super Admin OK: " + sup_resp.description);
                        return true;
                    }
                    else
                    {
                        _logger.LogError("Check Super Admin Failed: " + sup_resp.description);
                        return false;
                    }
                }
                else
                {
                    var result_error = response.Content.ReadAsStringAsync().Result;
                    sup_resp = JsonConvert.DeserializeObject<CheckSuperAdminResp>(result_error);

                    sup_resp.result = "error";
                    sup_resp.description = sup_resp.description;
                    _logger.LogError("Check Super Admin Failed: " + response.StatusCode);

                    return false;
                }
            }
            catch (Exception ex)
            {
                sup_resp.result = "error";
                sup_resp.description = ex.Message.ToString();
                _logger.LogError("Check Super Admin Exception: " + ex.Message.ToString());
                ex.StackTrace.ToString();

                return false;
            }
            finally
            {
                _logger.LogInformation("---------- End CheckSuperAdmin Session() ----------");
            }
        }
    }
}
