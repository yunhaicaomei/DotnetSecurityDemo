using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotnetSecurityDemo.Hash
{
    public class MD5CryptoServiceProviderHelper : HashAlgorithmHelper<MD5CryptoServiceProvider> { }
    public class SHA1CryptoServiceProviderHelper : HashAlgorithmHelper<SHA1CryptoServiceProvider> { }
    public class SHA256CryptoServiceProviderHelper : HashAlgorithmHelper<SHA256CryptoServiceProvider> { }
    public class SHA384CryptoServiceProviderHelper : HashAlgorithmHelper<SHA384CryptoServiceProvider> { }
    public class SHA512CryptoServiceProviderHelper : HashAlgorithmHelper<SHA512CryptoServiceProvider> { }

    public class RIPEMD160ManagedHelper : HashAlgorithmHelper<RIPEMD160Managed> { }
    public class SHA1ManagedHelper : HashAlgorithmHelper<SHA1Managed> { }
    public class SHA256ManagedHelper : HashAlgorithmHelper<SHA256Managed> { }
    public class SHA384ManagedHelper : HashAlgorithmHelper<SHA384Managed> { }
    public class SHA512ManagedHelper : HashAlgorithmHelper<SHA512Managed> { }

    public class MD5CngHelper : HashAlgorithmHelper<MD5Cng> { }
    public class SHA1CngHelper : HashAlgorithmHelper<SHA1Cng> { }
    public class SHA256CngHelper : HashAlgorithmHelper<SHA256Cng> { }
    public class SHA384CngHelper : HashAlgorithmHelper<SHA384Cng> { }
    public class SHA512CngHelper : HashAlgorithmHelper<SHA512Cng> { }
}
