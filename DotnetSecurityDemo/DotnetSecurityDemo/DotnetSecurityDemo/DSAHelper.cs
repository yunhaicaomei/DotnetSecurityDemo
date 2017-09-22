using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSecurityDemo
{
    /// <summary>
    /// RSA非对称签名算法
    /// </summary>
    public class DSAHelper : AsymmetricAlgorithm<DSACryptoServiceProvider>
    {
        static DSAHelper()
        {
            DSACryptoServiceProvider.UseMachineKeyStore = true;
        }

        public static void Create(out string publicKey, out string privateKey, int keySize = 1024)
        {
            DSACryptoServiceProvider provider = new DSACryptoServiceProvider(keySize);
            KeyGenerator.CreateAsymmetricAlgorithmKey(out publicKey, out privateKey, provider);
        }  

        public static string SignData(string privatekey, string content)
        {
            return Execute(privatekey,
                algorithm => Convert.ToBase64String(algorithm.SignData(Encoding.UTF8.GetBytes(content))));
        }

        public static bool VerifyData(string publicKey, string content, string signature)
        {
            return Execute(publicKey,
                algorithm => algorithm.VerifyData(Encoding.UTF8.GetBytes(content), Convert.FromBase64String(signature)));
        }
    }
}
