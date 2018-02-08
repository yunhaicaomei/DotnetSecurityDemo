using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSecurityDemo
{
    public class HMACMD5Helper : KeyedHashAlgorithmHelper<HMACMD5>
    {
    }
    public class HMACRIPEMD160Helper : KeyedHashAlgorithmHelper<HMACRIPEMD160>
    {
    }
    public class HMACSHA1Helper : KeyedHashAlgorithmHelper<HMACSHA1>
    {
    }
    public class HMACSHA256Helper : KeyedHashAlgorithmHelper<HMACSHA256>
    {
    }
    public class HMACSHA384Helper : KeyedHashAlgorithmHelper<HMACSHA384>
    {
    }
    public class HMACSHA512Helper : KeyedHashAlgorithmHelper<HMACSHA512>
    {
    }
    public class MACTripleDESHelper : KeyedHashAlgorithmHelper<MACTripleDES>
    {
    }
}
