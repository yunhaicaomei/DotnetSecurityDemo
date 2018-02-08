using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSecurityDemo
{

    /// <summary>
    /// 对称加密
    /// </summary>
    public class SymmetricAlgorithmHelper
    {
        /// <summary>
        /// 解密方法（对称加密解密）
        /// </summary>
        /// <param name="encryptText"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public static string Decrypt<T>(string encryptText, string key, string IV) where T : SymmetricAlgorithm, new()
        {
            try
            {
                byte[] rgbKey = Convert.FromBase64String(key);
                byte[] rgbIV = Convert.FromBase64String(IV);
                T provider = new T();
                provider.Mode = CipherMode.ECB;
                provider.Key = rgbKey;
                provider.IV = rgbIV;
                ICryptoTransform transform1 = provider.CreateDecryptor(provider.Key, provider.IV);
                byte[] buffer3 = Convert.FromBase64String(encryptText);
                MemoryStream stream1 = new MemoryStream();
                CryptoStream stream2 = new CryptoStream(stream1, transform1, CryptoStreamMode.Write);
                stream2.Write(buffer3, 0, buffer3.Length);
                stream2.FlushFinalBlock();
                stream2.Close();
                return Encoding.UTF8.GetString(stream1.ToArray());
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        /// <summary>
        /// 加密方法（对称加密解密）
        /// </summary>
        /// <param name="val"></param>
        /// <param name="key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        public static string Encrypt<T>(string val, string key, string IV) where T : SymmetricAlgorithm, new()
        {
            try
            {
                byte[] rgbKey = Convert.FromBase64String(key);
                byte[] rgbIV = Convert.FromBase64String(IV);

                T provider1 = new T();
                provider1.Mode = CipherMode.ECB;
                provider1.Key = rgbKey;
                provider1.IV = rgbIV;
                ICryptoTransform transform1 = provider1.CreateEncryptor(provider1.Key, provider1.IV);
                byte[] buffer3 = Encoding.Default.GetBytes(val);
                MemoryStream stream1 = new MemoryStream();
                CryptoStream stream2 = new CryptoStream(stream1, transform1, CryptoStreamMode.Write);
                stream2.Write(buffer3, 0, buffer3.Length);
                stream2.FlushFinalBlock();
                stream2.Close();
                return Convert.ToBase64String(stream1.ToArray());
            }
            catch (Exception ex)
            {
                throw;
            }
        }
    }
}
