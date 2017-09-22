using DotnetSecurityDemo.Hash;
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
            TestSymmetricAlgorithm();
            //测试哈希算法
            TestHashAlgorithm();
            //测试非对称加密算法
            TestAsymmetricAlgorithm();

            Console.Read();
        }

        private static void TestSymmetricAlgorithm()
        {
            //128~256
            TestSymmetricAlgorithmHaldle<System.Security.Cryptography.AesCryptoServiceProvider>(128);
            //64
            TestSymmetricAlgorithmHaldle<System.Security.Cryptography.DESCryptoServiceProvider>(64);
            //64
            TestSymmetricAlgorithmHaldle<System.Security.Cryptography.RC2CryptoServiceProvider>(64);
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
            string encryptText = SymmetricAlgorithmHelper.Encrypt<T>(line, key, iv);
            Console.WriteLine(encryptText);
            //解密
            string decryptText = SymmetricAlgorithmHelper.Decrypt<T>(encryptText, key, iv);
            Console.WriteLine(decryptText);
        }

        private static void TestHashAlgorithm()
        {
            string inputValue = Console.ReadLine();
            Console.WriteLine("inputValue=" + inputValue);

            Console.WriteLine("Provider:");
            Console.WriteLine("MD5CryptoServiceProvider=" + SHA512CryptoServiceProviderHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA1CryptoServiceProvider=" + MD5CryptoServiceProviderHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA256CryptoServiceProvider=" + SHA1CryptoServiceProviderHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA384CryptoServiceProvider=" + SHA256CryptoServiceProviderHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA512CryptoServiceProvider=" + SHA384CryptoServiceProviderHelper.GetHashBase64String(inputValue));
            
            Console.WriteLine("Managed:");
            Console.WriteLine("RIPEMD160Managed=" + RIPEMD160ManagedHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA1Managed=" + SHA1ManagedHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA256Managed=" + SHA256ManagedHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA384Managed=" + SHA384ManagedHelper.GetHashBase64String(inputValue));
            Console.WriteLine("SHA512Managed=" + SHA512ManagedHelper.GetHashBase64String(inputValue));


            Console.WriteLine("Cng:");
            Console.WriteLine("MD5Cng=" + MD5CngHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA1Cng=" + SHA1CngHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA256Cng=" + SHA256CngHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA384Cng=" + SHA384CngHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA512Cng=" + SHA512CngHelper.GetHashHexString(inputValue));

            Console.WriteLine("Provider.HexString:");
            Console.WriteLine("MD5CryptoServiceProvider=" + SHA512CryptoServiceProviderHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA1CryptoServiceProvider=" + MD5CryptoServiceProviderHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA256CryptoServiceProvider=" + SHA1CryptoServiceProviderHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA384CryptoServiceProvider=" + SHA256CryptoServiceProviderHelper.GetHashHexString(inputValue));
            Console.WriteLine("SHA512CryptoServiceProvider=" + SHA384CryptoServiceProviderHelper.GetHashHexString(inputValue));

            string inputSecret = Console.ReadLine();
            Console.WriteLine("inputSecret=" + inputSecret);

            Console.WriteLine("HMAC.HexString:");
            Console.WriteLine("HMACMD5=" + HMACMD5Helper.GetHmacHexString(inputSecret, inputValue));
            Console.WriteLine("HMACRIPEMD160=" + HMACRIPEMD160Helper.GetHmacHexString(inputSecret, inputValue));
            Console.WriteLine("HMACSHA1=" + HMACSHA1Helper.GetHmacHexString(inputSecret, inputValue));
            Console.WriteLine("HMACSHA256=" + HMACSHA256Helper.GetHmacHexString(inputSecret, inputValue));
            Console.WriteLine("HMACSHA384=" + HMACSHA384Helper.GetHmacHexString(inputSecret, inputValue));
            Console.WriteLine("HMACSHA512=" + HMACSHA512Helper.GetHmacHexString(inputSecret, inputValue));
            Console.WriteLine("MACTripleDES=" + MACTripleDESHelper.GetHmacHexString(inputSecret, inputValue));
            
            Console.WriteLine("PBKDF2:");
            Console.WriteLine("PBKDF2=" + PBKDF2Helper.PBKDF2HexString(inputValue, 128, 1000));
            Console.WriteLine("PBKDF2=" + PBKDF2Helper.PBKDF2(inputValue, ""));
        }

        private static void TestAsymmetricAlgorithm()
        {
            Console.WriteLine("input value");
            string content = Console.ReadLine();
            string publicKey, privateKey;
            RSAHelper.Create(out publicKey, out privateKey);

            //RSA加密
            var encryptString = RSAHelper.Encrypt(publicKey, content);
            Console.WriteLine("content=" + content);
            Console.WriteLine("encryptString=" + encryptString);
            var dencryptString = RSAHelper.Decrypt(privateKey, encryptString);
            Console.WriteLine("dencryptString=" + dencryptString);

            //RSA签名
            var singData = RSAHelper.SignData(privateKey, content);
            Console.WriteLine("singData=" + singData);
            bool verifyResult = RSAHelper.VerifyData(publicKey, content, singData);
            Console.WriteLine("verifyResult=" + verifyResult);

            DSAHelper.Create(out publicKey, out privateKey);
            //DSA签名
            singData = DSAHelper.SignData(privateKey, content);
            Console.WriteLine("singData=" + singData);
            verifyResult = DSAHelper.VerifyData(publicKey, content, singData);
            Console.WriteLine("verifyResult=" + verifyResult);
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
