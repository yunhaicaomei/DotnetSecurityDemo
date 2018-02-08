using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace DotnetSecurityDemo
{
    /// <summary>
    /// 哈希算法
    /// </summary>
    public class HashAlgorithmHelper<T> where T : HashAlgorithm, new()
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="val"></param>
        /// <returns></returns>
        public static byte[] GetHash(string val)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(val);
            T hash = new T();
            byte[] t = hash.ComputeHash(buffer);
            return t;
        }

        public static byte[] GetHash(System.IO.Stream val) 
        {
            T hash = new T();
            byte[] t = hash.ComputeHash(val);
            return t;
        }

        public static string GetHashBase64String(string input)
        {
            var bytes = GetHash(input);
            return Convert.ToBase64String(bytes);
        }

        public static string GetHashHexString(string input) 
        {
            var bytes = GetHash(input);
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
