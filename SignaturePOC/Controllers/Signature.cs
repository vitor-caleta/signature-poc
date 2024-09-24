using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using SignaturePOC.Services;

namespace SignaturePOC.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class Signature : ControllerBase
    {
        private readonly ISignatureService _signatureService;

        public Signature(ISignatureService signatureService){
            _signatureService = signatureService;
        }

        [HttpPost("/verify")]
        public IActionResult VerifySignature(){
            using (var memoryStream = new MemoryStream())
            {
            HttpContext.Request.Headers.TryGetValue("X-Auth-Signature", out var signature);
            HttpContext.Request.Body.CopyToAsync(memoryStream);
            var rawBody = memoryStream.ToArray();

            var result = _signatureService.VerifySignature(rawBody, signature.ToString());
            return Ok(result);
            }
        }

        [HttpPost("/create")]
        public IActionResult CreateSignature(){
            var result = _signatureService.CreateSignature();
            return Ok(result);
        }
    }
}