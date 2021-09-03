using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http;

namespace ScannerAPI
    {

    public class MVCConnection
    {
        public iam_tokenClass iam_token = new iam_tokenClass();
        public mvc_authinfoClass mvc_authinfo = new mvc_authinfoClass();
        public class iam_tokenClass
        {
            public string token_type;
            public DateTime expires_at;
            public string access_token;

        }

        public class mvc_authinfoClass
        {
            public string token_type;
            public string access_token;
            public string refresh_token;
            public string tenant_ID;
            public string tenant_Name;
            public string userID;
            public string email;
            public string users;
            public DateTime expires_at;
        }
        public bool isAuthenticated()
        {
            if (string.IsNullOrEmpty(iam_token.access_token) || DateTime.Now > iam_token.expires_at)
            {
                return false;
            }
            else
            {
                return true;
            }

        }
        public async Task<bool> AuthenticateAsync(string username, string password, string bpsTenantid, string env, ILogger log)
        {
            string iam_url = "https://iam.mcafee-cloud.com/iam/v1.1/token";  //hard coded

            if (string.IsNullOrEmpty(env)) { env = "www.myshn.net"; }


            var iam_payload = new Dictionary<string, string>
                    {
                        { "client_id", "0oae8q9q2y0IZOYUm0h7" },
                        { "grant_type", "password" },
                        { "username", username },
                        { "password", password },
                        { "scope", "shn.con.r web.adm.x web.rpt.x web.rpt.r web.lst.x web.plc.x web.xprt.x web.cnf.x uam:admin" },
                        { "tenant_id", bpsTenantid },
                    };

            try  //Authenticate to McAfee IAM
            {
                HttpClient client = new HttpClient();
                var iam_data = new FormUrlEncodedContent(iam_payload);
                var iam_response = await client.PostAsync(iam_url, iam_data);

                if (iam_response.StatusCode != HttpStatusCode.OK)
                {
                    //Got something other than OK, error out
                    log.LogInformation("Unsuccessful authentication of " + username + "to McAfee IAM.  HTTP Status: " + iam_response.StatusCode.ToString());
                    return false;

                }
                else
                {
                    var iam_responseString = await iam_response.Content.ReadAsStringAsync();
                    var iam_responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(iam_responseString);

                    iam_token.access_token = iam_responseData["access_token"];
                    iam_token.expires_at = DateTime.Now.AddSeconds(int.Parse(iam_responseData["expires_in"]));
                    iam_token.token_type = iam_responseData["token_type"];

                    //TODO write token information to class
                    log.LogInformation("Successful authentication of " + username + "to McAfee IAM and fetch of iam_token");

                }
            }
            catch (Exception e)
            {
                log.LogInformation("Exception in IAM authentication: " + e.Message);
                return false;
            }

            string mvc_url = "https://" + env + "/neo/neo-auth-service/oauth/token?grant_type=iam_token";
            try //Authenticate to MVISION Cloud
            {
                HttpClient mvc_client = new HttpClient();

                var mvc_request = new HttpRequestMessage()
                {
                    RequestUri = new Uri(mvc_url),
                    Method = HttpMethod.Post
                };
                mvc_request.Headers.Add("x-iam-token", iam_token.access_token);

                var mvc_response = await mvc_client.SendAsync(mvc_request);

                if (mvc_response.StatusCode != HttpStatusCode.OK)
                {
                    //Got something other than OK, error out
                    log.LogInformation("Unsuccessful authentication of " + username + "to MVISION Cloud.  HTTP Status: " + mvc_response.StatusCode.ToString());
                    return false;
                }
                else
                {
                    var mvc_responseString = await mvc_response.Content.ReadAsStringAsync();
                    var mvc_responseData = JsonConvert.DeserializeObject<Dictionary<string,string>>(mvc_responseString);

                    mvc_authinfo.token_type = mvc_responseData["token_type"];
                    mvc_authinfo.access_token = mvc_responseData["access_token"];
                    mvc_authinfo.refresh_token = mvc_responseData["refresh_token"];
                    mvc_authinfo.tenant_ID = mvc_responseData["tenantID"];
                    mvc_authinfo.tenant_Name = mvc_responseData["tenantName"];
                    mvc_authinfo.userID = mvc_responseData["userId"];
                    mvc_authinfo.email = mvc_responseData["email"];
                    mvc_authinfo.expires_at = DateTime.Now.AddSeconds(int.Parse(mvc_responseData["expires_in"]));

                    log.LogInformation("Successful authentication of " + username + "to MVISION Cloud, got access token.");
                    return true;
                }

            }
            catch (Exception e)
            {
                log.LogInformation("Exception in MVISION Cloud authentication: " + e.Message);
                return false;
            }

        }
    }

    public static class DLPScan
    {
        static MVCConnection conn = new MVCConnection();
        [FunctionName("DLPScan")]
        public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req, ILogger log)
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            string urlToScan = req.Query["url"];
            string fileName = Path.GetFileName(urlToScan);

            string env = "www.myshn.net";  //TODO: get from env variable
            string policyid = "520065"; //TODO: get form env variable

            MemoryStream responseStream;

            if (conn.isAuthenticated())
            {
                log.LogInformation("Already authenticated...");
                return new OkObjectResult("Already authenticated...");
            }
            else
            {
                bool isAuthenticated = await conn.AuthenticateAsync("nate@mvision-ebc.com", "9hy%QP1hxoX&", "A9DD97B4-FBB7-49F8-80A0-8A2164A1E17C", "", log);
                log.LogInformation("Authenticating, result: " + isAuthenticated.ToString());
            }

            string mvc_url = "https://" + env + "/neo/zeus/v1/admin/content-parser/policy/evaluation/silo/" + conn.mvc_authinfo.tenant_ID + "/" + "1";
            log.LogInformation("Calling MVC API: " + mvc_url);

            try //Fetch file and DLP API Request
            {
                responseStream = new MemoryStream(new WebClient().DownloadData(urlToScan));
                log.LogInformation("Sucessfully fetched " + fileName);

                HttpClient mvc_client = new HttpClient();
                mvc_client.DefaultRequestHeaders.Add("x-access-token", conn.mvc_authinfo.access_token);
                mvc_client.DefaultRequestHeaders.Add("x-refresh-token", conn.mvc_authinfo.refresh_token);

                var formData = new MultipartFormDataContent();
                formData.Add(new ByteArrayContent(responseStream.ToArray()), "file", fileName);
                formData.Add(new StringContent("1"), "numOfTimes");
                formData.Add(new StringContent(policyid), "policy_ids");

                var mvc_response = await mvc_client.PostAsync(mvc_url, formData);

                var mvc_responseString = await mvc_response.Content.ReadAsStringAsync();
                log.LogInformation(mvc_responseString);
                var mvc_responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(mvc_responseString);

                log.LogInformation("Processed DLP Policy Evaluation: Filename=" + mvc_responseData["fileName"] + " Policy Name=" + mvc_responseData["policy_name"] + " Result=" + mvc_responseData["evaluation_result"]);

            }
            catch (Exception e)
            {
                log.LogInformation("Exception in DLP API call: " + e.Message);

            }


            return new OkObjectResult("DLP Result:");

        }

     }
}

