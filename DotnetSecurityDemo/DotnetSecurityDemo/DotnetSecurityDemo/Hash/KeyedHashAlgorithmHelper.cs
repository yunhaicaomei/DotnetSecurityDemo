using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace DotnetSecurityDemo
{
    public class KeyedHashAlgorithmHelper<T> where T : KeyedHashAlgorithm, new()
    {
        public static byte[] GetHmac(string secret, string val)
        {
            T hmac = new T();
            if (secret != null)
            {
                hmac.Key = Encoding.UTF8.GetBytes(secret);
            }
            byte[] buffer = Encoding.UTF8.GetBytes(val);
            byte[] t = hmac.ComputeHash(buffer);
            return t;
        }

        public static byte[] GetHmac(string secret, Stream val)
        {
            T hmac = new T();
            if (secret != null)
            {
                hmac.Key = Encoding.UTF8.GetBytes(secret);
            }
            byte[] t = hmac.ComputeHash(val);
            return t;
        }

        public static string GetHmacBase64String(string secret, string input)
        {
            var bytes = GetHmac(secret, input);
            return Convert.ToBase64String(bytes);
        }

        public static string GetHmacHexString(string secret, string input)
        {
            var bytes = GetHmac(secret, input);
            StringBuilder returnStr = new StringBuilder();
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    returnStr.Append(bytes[i].ToString("X2"));
                }
            }
            return returnStr.ToString();
        }

        public static string GetHmacBase64String(string secret, Stream input)
        {
            var bytes = GetHmac(secret, input);
            return Convert.ToBase64String(bytes);
        }

        public static string GetHmacHexString(string secret, Stream input)
        {
            var bytes = GetHmac(secret, input);
            StringBuilder returnStr = new StringBuilder();
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    returnStr.Append(bytes[i].ToString("X2"));
                }
            }
            return returnStr.ToString();
        }
    }
}
