﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSecurityDemo
{
    public class KeyGenerator
    {
        /// <summary>  
        /// 随机生成秘钥（对称算法）
        /// </summary>
        /// <param name="key">秘钥(base64格式)</param>
        /// <param name="iv">iv向量(base64格式)</param>
        /// <param name="keySize">要生成的KeySize，每8个byte是一个字节，注意每种算法支持的KeySize均有差异，实际可通过输出LegalKeySizes来得到支持的值</param>  
        public static void CreateSymmetricAlgorithmKey<T>(out string key, out string iv, int keySize)
            where T : SymmetricAlgorithm, new()
        {
            using (T t = new T())
            {
#if DEBUG
                Console.WriteLine(string.Join("", t.LegalKeySizes.Select(k => string.Format("MinSize:{0} MaxSize:{1} SkipSize:{2}", k.MinSize, k.MaxSize, k.SkipSize))));
#endif
                t.KeySize = keySize;
                t.GenerateIV();
                t.GenerateKey();
                iv = Convert.ToBase64String(t.IV);
                key = Convert.ToBase64String(t.Key);
            }
        }

        /// <summary>  
        /// 随机生成秘钥（非对称算法）
        /// </summary>  
        /// <typeparam name="T"></typeparam>
        /// <param name="publicKey">公钥（Xml格式）</param>
        /// <param name="privateKey">私钥（Xml格式）</param>
        public static void CreateAsymmetricAlgorithmKey<T>(out string publicKey, out string privateKey, T provider = null)
            where T : AsymmetricAlgorithm, new()
        {
            if (provider == null)
            {
                provider = new T();
            }
            using (provider)
            {
#if DEBUG
                Console.WriteLine(string.Join("", provider.LegalKeySizes.Select(k => string.Format("MinSize:{0} MaxSize:{1} SkipSize:{2}", k.MinSize, k.MaxSize, k.SkipSize))));
#endif
                publicKey = provider.ToXmlString(false);
                privateKey = provider.ToXmlString(true);
            }
        }

        public static void Test()
        {
            string key, iv;
            KeyGenerator.CreateSymmetricAlgorithmKey<TripleDESCryptoServiceProvider>(out key, out iv, 128);
            Console.WriteLine("key=" + key + "," + key.Length);
            KeyGenerator.CreateSymmetricAlgorithmKey<TripleDESCryptoServiceProvider>(out key, out iv, 192);
            Console.WriteLine("key=" + key + "," + key.Length);

            string privateKey, publicKey;
            for (var i = 800; i < 2000; i += 8)
            {
                KeyGenerator.CreateAsymmetricAlgorithmKey<RSACryptoServiceProvider>(out publicKey, out privateKey);
                Console.WriteLine("publicKey=" + publicKey + "," + publicKey.Length);
                Console.WriteLine("privateKey=" + privateKey + "," + privateKey.Length);
            }
        }
    }
}
