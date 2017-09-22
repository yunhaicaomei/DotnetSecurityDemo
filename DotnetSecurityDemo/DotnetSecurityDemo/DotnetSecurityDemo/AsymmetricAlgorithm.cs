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
    /// 非对称加密
    /// </summary>
    public class AsymmetricAlgorithm<T> where T : AsymmetricAlgorithm, new()
    {
        /// <summary>
        /// 执行AsymmetricAlgorithm的方法
        /// </summary>
        /// <typeparam name="TResult"></typeparam>
        /// <param name="key">密钥</param>
        /// <param name="function">外部传入的逻辑</param>
        /// <returns></returns>
        protected static TResult Execute<TResult>(string key, Func<T, TResult> function)
        {
            using (T algorithm = new T())
            {
                algorithm.FromXmlString(key);
                return function(algorithm);
            }
        }

        /// <summary>
        /// 按默认规则生成公钥、私钥
        /// </summary>
        /// <param name="publicKey">公钥（Xml格式）</param>
        /// <param name="privateKey">私钥（Xml格式）</param>
        protected static void Create(out string publicKey, out string privateKey)
        {
            KeyGenerator.CreateAsymmetricAlgorithmKey<T>(out publicKey, out privateKey);
        }
    }
}
