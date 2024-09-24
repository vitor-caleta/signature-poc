using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Newtonsoft.Json;

interface ISignaturePOC{

}

namespace SignaturePOC.Services
{
     public interface ISignatureService
    {
        bool VerifySignature(byte[] rawBody, string header);
        byte[] CreateSignature();
    }

    public class SignatureService:ISignatureService
    {
        private readonly string caletaKey = File.ReadAllText("./keys/caletaKey");
        private readonly string privateKeyPem = File.ReadAllText("./keys/privateKey");
        public bool VerifySignature(byte[] rawBody, string header)
        {
            byte[] signature = Convert.FromBase64String(header);
            byte[] hash = SHA256.HashData(rawBody);

            using RSA rsa = RSA.Create();
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

        public byte[] CreateSignature()
        {
            RSA _privateKey = RSA.Create();
            _privateKey.ImportFromPem(privateKeyPem.ToCharArray());

            var payload = new Dictionary<string, string>
            {
                {"game_code", "cg_sample"},
                {"operator_id", "sample"}
            };
            Console.Write(payload);

            var jsonPayload = JsonConvert.SerializeObject(payload);
            Console.Write(jsonPayload);
            var encodedPayload = Encoding.UTF8.GetBytes(jsonPayload);
            byte[] hash = SHA256.HashData(encodedPayload);

            return _privateKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}