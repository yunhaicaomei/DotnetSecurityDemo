using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSecurityDemo
{
    /// <summary>
    /// RSA非对称加密及签名算法
    /// </summary>
    public class RSAHelper : AbsAsymmetricAlgorithm<RSACryptoServiceProvider>
    {
        static RSAHelper()
        {
            RSACryptoServiceProvider.UseMachineKeyStore = true;
        }

        public static void Create(out string publicKey, out string privateKey, int keySize = 1024)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider(keySize);
            KeyGenerator.CreateAsymmetricAlgorithmKey(out publicKey, out privateKey, provider);
        }  

        public static string Encrypt(string publickey, string content, bool fOAEP = false)
        {
            return Execute(publickey,
                algorithm => Convert.ToBase64String(algorithm.Encrypt(Encoding.UTF8.GetBytes(content), fOAEP)));
        }

        public static string Decrypt(string privatekey, string content, bool fOAEP = false)
        {
            return Execute(privatekey,
                algorithm => Encoding.UTF8.GetString(algorithm.Decrypt(Convert.FromBase64String(content), fOAEP)));
        }

        public static string SignData(string privatekey, string content, SignType halg = SignType.SHA1)
        {
            return Execute(privatekey,
                algorithm => Convert.ToBase64String(algorithm.SignData(Encoding.UTF8.GetBytes(content), halg.ToString())));
        }

        public static bool VerifyData(string publicKey, string content, string signature, SignType halg = SignType.SHA1)
        {
            return Execute(publicKey,
                algorithm => algorithm.VerifyData(Encoding.UTF8.GetBytes(content), halg.ToString(), Convert.FromBase64String(signature)));
        }

        public enum SignType
        {
            SHA1, SHA256, SHA384, SHA512, MD5
        }
    }
}
