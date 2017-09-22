using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace DotnetSecurityDemo
{
    class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            //测试对称加密算法
            //TestSymmetricAlgorithm();
            //测试哈希算法
            TestHashAlgorithm();

            Console.Read();
        }

        private static void TestSymmetricAlgorithm()
        {
            //64
            TestSymmetricAlgorithmHaldle<System.Security.Cryptography.DESCryptoServiceProvider>(64);
            //128~256
            TestSymmetricAlgorithmHaldle<System.Security.Cryptography.RijndaelManaged>(128);
            //128~192
            TestSymmetricAlgorithmHaldle<System.Security.Cryptography.TripleDESCryptoServiceProvider>(128);
        }

        private static void TestSymmetricAlgorithmHaldle<T>(int keySize) where T : SymmetricAlgorithm, new()
        {
            string key, iv;
            //创建密钥
            KeyGenerator.CreateSymmetricAlgorithmKey<T>(out key, out iv, keySize);

            string line = Console.ReadLine();
            //加密
            string encryptText = SymmetricAlgorithmHaldle.Encrypt<T>(line, key, iv);
            Console.WriteLine(encryptText);
            //解密
            string decryptText = SymmetricAlgorithmHaldle.Decrypt<T>(encryptText, key, iv);
            Console.WriteLine(decryptText);
        }

        private static void TestHashAlgorithm()
        {
            string line = Console.ReadLine();
            string str;
            var bytes = HashAlgorithmHandle.GetHash<System.Security.Cryptography.MD5CryptoServiceProvider>(line);

            Console.WriteLine("Provider:");
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA1CryptoServiceProvider>(line);
            Console.WriteLine("SHA1CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA256CryptoServiceProvider>(line);
            Console.WriteLine("SHA256CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA384CryptoServiceProvider>(line);
            Console.WriteLine("SHA384CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA512CryptoServiceProvider>(line);
            Console.WriteLine("SHA512CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.MD5CryptoServiceProvider>(line);
            Console.WriteLine("MD5CryptoServiceProvider=" + str);


            Console.WriteLine("Managed:");
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA1Managed>(line);
            Console.WriteLine("SHA1CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA256Managed>(line);
            Console.WriteLine("SHA256CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA384Managed>(line);
            Console.WriteLine("SHA384CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.SHA512Managed>(line);
            Console.WriteLine("SHA512CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashBase64String<System.Security.Cryptography.RIPEMD160Managed>(line);
            Console.WriteLine("RIPEMD160Managed=" + str);


            Console.WriteLine("Cng:");
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA1Cng>(line);
            Console.WriteLine("SHA1CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA256Cng>(line);
            Console.WriteLine("SHA256CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA384Cng>(line);
            Console.WriteLine("SHA384CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA512Cng>(line);
            Console.WriteLine("SHA512CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.MD5Cng>(line);
            Console.WriteLine("MD5CryptoServiceProvider=" + str);


            Console.WriteLine("Provider.HexString:");
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA1CryptoServiceProvider>(line);
            Console.WriteLine("SHA1CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA256CryptoServiceProvider>(line);
            Console.WriteLine("SHA256CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA384CryptoServiceProvider>(line);
            Console.WriteLine("SHA384CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.SHA512CryptoServiceProvider>(line);
            Console.WriteLine("SHA512CryptoServiceProvider=" + str);
            str = HashAlgorithmHandle.GetHashHexString<System.Security.Cryptography.MD5CryptoServiceProvider>(line);
            Console.WriteLine("MD5CryptoServiceProvider=" + str);


            Console.WriteLine("HMAC.HexString:");
            str = HashAlgorithmHandle.GetHmacHexString<System.Security.Cryptography.HMACMD5>(line, line);
            Console.WriteLine("HMACMD5=" + str);
            str = HashAlgorithmHandle.GetHmacHexString<System.Security.Cryptography.HMACRIPEMD160>(line, line);
            Console.WriteLine("HMACRIPEMD160=" + str);
            str = HashAlgorithmHandle.GetHmacHexString<System.Security.Cryptography.HMACSHA1>(line, line);
            Console.WriteLine("HMACSHA1=" + str);
            str = HashAlgorithmHandle.GetHmacHexString<System.Security.Cryptography.HMACSHA256>(line, line);
            Console.WriteLine("HMACSHA256=" + str);
            str = HashAlgorithmHandle.GetHmacHexString<System.Security.Cryptography.HMACSHA384>(line, line);
            Console.WriteLine("HMACSHA384=" + str);
            str = HashAlgorithmHandle.GetHmacHexString<System.Security.Cryptography.HMACSHA512>(line, line);
            Console.WriteLine("HMACSHA512=" + str);

            str = HashAlgorithmHandle.PBKDF2HexString(line, 128, 1000);
            Console.WriteLine("PBKDF2=" + str);
            str = HashAlgorithmHandle.PBKDF2(line, "");
            Console.WriteLine("PBKDF2=" + str);
        }

        private static void Encryption()
        {
            // 创建一个用于加密密钥的非对称密钥
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            // 加载一个公开密钥
            XmlDocument pubKeys = new XmlDocument();
            //pubKeys.Load(Application.StartupPath + "\\xml.dev.keys.public");
            // 使用公开密钥加密密钥
            rsa.FromXmlString(pubKeys.OuterXml);
        }
    }
}
