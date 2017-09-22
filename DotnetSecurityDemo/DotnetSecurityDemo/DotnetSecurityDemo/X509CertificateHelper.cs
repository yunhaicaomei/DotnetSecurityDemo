using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSecurityDemo
{
    public class X509CertificateHelper
    {
        public static void Append()
        {
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(CheckValidationResult);

            //证书已上传到对应目录
            string certPath = "Root" + "/weixinApp/cert/apiclient_cert.p12";
            X509Certificate2 cert = new X509Certificate2(certPath, "SSLCERT_PASSWORD");

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("url");
            request.ClientCertificates.Add(cert);
            //logic

        }

        private static bool CheckValidationResult(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            if (errors == SslPolicyErrors.None)
                return true;
            return false;
        }
    }
}
