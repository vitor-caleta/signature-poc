using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

interface ISignaturePOC{

}

namespace SignaturePOC.Services
{
     public interface ISignatureService
    {
        bool VerifySignature(byte[] rawBody, string header);
        string CreateSignature();
    }

    public class SignatureService:ISignatureService
    {
        private readonly string caletaKey = File.ReadAllText("./keys/caletaKey");
        //private readonly string privateKey = File.ReadAllText("./keys/privateKey");

        public bool VerifySignature(byte[] rawBody, string header)
        {
            byte[] signature = Convert.FromBase64String(header);
            byte[] hash = SHA256.HashData(rawBody);

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(caletaKey.ToCharArray());

                try
                {
                    return rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
                catch (CryptographicException)
                {
                    return false;
                }
            }
        }

        public string CreateSignature(){
            return "";  
        }
    }
}