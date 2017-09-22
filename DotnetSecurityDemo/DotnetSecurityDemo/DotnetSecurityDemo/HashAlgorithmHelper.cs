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
    public class HashAlgorithmHelper
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="val"></param>
        /// <returns></returns>
        public static byte[] GetHash<T>(string val) where T : HashAlgorithm, new()
        {
            byte[] buffer = Encoding.UTF8.GetBytes(val);
            T hash = new T();
            byte[] t = hash.ComputeHash(buffer);
            return t;
        }

        public static byte[] GetHash<T>(System.IO.Stream val) where T : HashAlgorithm, new()
        {
            T hash = new T();
            byte[] t = hash.ComputeHash(val);
            return t;
        }

        public static string GetHashBase64String<T>(string input) where T : HashAlgorithm, new()
        {
            var bytes = GetHash<T>(input);
            return Convert.ToBase64String(bytes);
        }

        public static string GetHashHexString<T>(string input) where T : HashAlgorithm, new()
        {
            var bytes = GetHash<T>(input);
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

        public static byte[] GetHmac<T>(string secret, string val) where T : KeyedHashAlgorithm, new()
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

        public static string GetHmacBase64String<T>(string secret, string input) where T : KeyedHashAlgorithm, new()
        {
            var bytes = GetHmac<T>(secret, input);
            return Convert.ToBase64String(bytes);
        }

        public static string GetHmacHexString<T>(string secret, string input) where T : KeyedHashAlgorithm, new()
        {
            var bytes = GetHmac<T>(secret, input);
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

        public static string PBKDF2HexString(string val, int saltSize, int iterations)
        {
            Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(val, saltSize, iterations);
            byte[] bytes = rfc.GetBytes(rfc.Salt.Length / 8);
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


        /// <summary>
        /// 计算PBKDF2哈希密码
        /// </summary>
        /// <param name="password">需要加密的明文密码</param>
        /// <param name="salt">盐增加调味 增加密码破解难度</param>
        /// <param name="iterations">迭代次数</param>
        /// <param name="bytes">计算密码后的 哈希长度</param>
        /// <returns></returns>
        public static string PBKDF2(string pwdValue, string saltValue)
        {
            byte[] data = System.Text.UTF8Encoding.UTF8.GetBytes(pwdValue);
            byte[] salt = System.Text.UTF8Encoding.UTF8.GetBytes(saltValue);
            if (salt.Length < 8)
            {
                salt = new byte[8];
            }
            // AesManaged - 高级加密标准(AES) 对称算法的管理类
            System.Security.Cryptography.AesManaged aes = new System.Security.Cryptography.AesManaged();
            // Rfc2898DeriveBytes - 通过使用基于 HMACSHA1 的伪随机数生成器，实现基于密码的密钥派生功能 (PBKDF2 - 一种基于密码的密钥派生函数)
            // 通过 密码 和 salt 派生密钥
            System.Security.Cryptography.Rfc2898DeriveBytes rfc = new System.Security.Cryptography.Rfc2898DeriveBytes(pwdValue, salt);
            /**/
            /*
             * AesManaged.BlockSize - 加密操作的块大小（单位：bit）
             * AesManaged.LegalBlockSizes - 对称算法支持的块大小（单位：bit）
             * AesManaged.KeySize - 对称算法的密钥大小（单位：bit）
             * AesManaged.LegalKeySizes - 对称算法支持的密钥大小（单位：bit）
             * AesManaged.Key - 对称算法的密钥
             * AesManaged.IV - 对称算法的密钥大小
             * Rfc2898DeriveBytes.GetBytes(int 需要生成的伪随机密钥字节数) - 生成密钥
             */
            aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
            aes.KeySize = aes.LegalKeySizes[0].MaxSize;
            aes.Key = rfc.GetBytes(aes.KeySize / 8);
            aes.IV = rfc.GetBytes(aes.BlockSize / 8);
            // 用当前的 Key 属性和初始化向量 IV 创建对称加密器对象
            System.Security.Cryptography.ICryptoTransform encryptTransform = aes.CreateEncryptor();
            // 加密后的输出流
            System.IO.MemoryStream encryptStream = new System.IO.MemoryStream();
            // 将加密后的目标流（encryptStream）与加密转换（encryptTransform）相连接
            System.Security.Cryptography.CryptoStream encryptor = new System.Security.Cryptography.CryptoStream
                (encryptStream, encryptTransform, System.Security.Cryptography.CryptoStreamMode.Write);
            // 将一个字节序列写入当前 CryptoStream （完成加密的过程）
            encryptor.Write(data, 0, data.Length);
            encryptor.Close();
            // 将加密后所得到的流转换成字节数组，再用Base64编码将其转换为字符串
            string encryptedString = Convert.ToBase64String(encryptStream.ToArray());
            return encryptedString;
        }
    }
}
