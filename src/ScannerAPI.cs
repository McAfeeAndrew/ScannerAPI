using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using Amazon.S3;
using Amazon.S3.Model;

namespace ScannerAPI
    {

     public static class Scanner
    {
        [FunctionName("AVScan")]
        public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req, ILogger log)
        {

            //Parse the request header for parameters
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            string urlToScan = req.Query["url"];
            string s3uriString = req.Query["s3uri"];

            //To add/replace support for accepting a file directly, instead of pulling a blob pass the
            //file into a memory or file stream here

            // EDIT ICAPServer, ICAPClient, and sICAPPort below if you will run the code directly on Azure (or pass them as environment variables)
            string ICAPServer = Environment.GetEnvironmentVariable("ICAPSERVER");
            if (string.IsNullOrEmpty(ICAPServer))
            {
                ICAPServer = "3.234.210.152";
                log.LogInformation("No ICAP server specified, defaulting to " + ICAPServer);
            }
            string ICAPClient = Environment.GetEnvironmentVariable("ICAPCLIENT");
            if (string.IsNullOrEmpty(ICAPClient))
            {
                ICAPClient = "192.168.0.1";
                log.LogInformation("No default ICAP client specified, defaulting to " + ICAPClient);
            }
            string sICAPPort = Environment.GetEnvironmentVariable("ICAPPORT");
            if (string.IsNullOrEmpty(sICAPPort))
            {
                sICAPPort = "1344";
                log.LogInformation("No default ICAP port specified, defaulting to " + sICAPPort);
            }

            log.LogInformation("C# HTTP triggered for AVScan function");

            string ICAPServiceName = "avscan";
            int ICAPPort = int.Parse(sICAPPort);

            ICAPClient.ICAP icapper = new ICAPClient.ICAP(ICAPServer, ICAPPort, ICAPServiceName, ICAPClient);

            try
            {

                if (urlToScan != null)
                {
                    //if a URL is provided, use that first
                    MemoryStream responseStream = new MemoryStream(new WebClient().DownloadData(urlToScan));
                    string fileName = Path.GetFileName(urlToScan);
                    jsonScanResult ScanResult = icapper.scanFile(responseStream, fileName);

                    string jsonScanResultString = JsonConvert.SerializeObject(ScanResult);

                    log.LogInformation(jsonScanResultString);

                    responseStream.Dispose();
                    icapper.Dispose();

                    return new OkObjectResult(JsonConvert.SerializeObject(ScanResult));
                }
                else if (s3uriString != null)
                {
                    //if S3 URI is provided, use that
                    
                    AmazonS3Client s3Client = new AmazonS3Client();
                    GetObjectRequest s3GetRequest = new GetObjectRequest();

                    Uri s3uri = new Uri(s3uriString);

                    s3GetRequest.BucketName = s3uri.Host;


                    char[] trimChars = { '/' };
                    s3GetRequest.Key = s3uri.AbsolutePath.Trim(trimChars); //need to remove leading or trailing slashes

                    log.LogInformation("Got URI: " + s3uriString + ", bucket=" + s3uri.Host + "key=" + s3uri.AbsolutePath);
                    GetObjectResponse response = await s3Client.GetObjectAsync(s3GetRequest);

                    MemoryStream responseStream = new MemoryStream();
                    response.ResponseStream.CopyTo(responseStream);

                    jsonScanResult ScanResult = icapper.scanFile(responseStream, s3GetRequest.Key);  //scan the file

                    string jsonScanResultString = JsonConvert.SerializeObject(ScanResult);

                    log.LogInformation(jsonScanResultString);

                    responseStream.Dispose();
                    s3Client.Dispose();
                    icapper.Dispose();

                    return new OkObjectResult(JsonConvert.SerializeObject(ScanResult));
                    
                }
                else
                {
                    return new OkObjectResult("Error: Did not receive any targets to scan");
                }
                
            }
            catch (Exception ex)
            {
                log.LogInformation("Scan failure, unknown Error: " + ex);
                return new OkObjectResult("Could not complete scan.  Exception:" + ex);
                
            }
            //return new OkObjectResult(responseMessage);
        }

    }

}

