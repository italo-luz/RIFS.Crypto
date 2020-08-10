using Microsoft.AspNetCore.Mvc; 
using Microsoft.Extensions.Logging;
using RIFS.Crypto.Entity;
using RIFS.Crypto.RSA;

namespace RIFS.Crypto.Sample.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class RSAController : ControllerBase
	{
		private readonly ILogger<RSAController> _logger;

		public RSAController(ILogger<RSAController> logger)
		{
			_logger = logger;
		}

		[HttpGet("GetKeys")]
		public RsaKey GetKeys()
		{
			return new RsaKey();
		}

        [HttpPost("EncryptSecurityText2048")]
        public string EncryptSecurityText2048(string dataToEncrypt)
        {
            var encryptedData = new SecurityText2048(dataToEncrypt);
            var result = encryptedData.Decrypt() + "\r\n" + encryptedData.Value;
            return result;
        }

        [HttpPost("Encrypt2048")]
		public string Encrypt2048(string publicKeyRsa, string dataToEncrypt)
		{
            var rsaEncrypt = new RsaEncrypt();
            var encryptedData = rsaEncrypt.Encrypt2048(publicKeyRsa, dataToEncrypt);
            return encryptedData;
		}

		[HttpPost("Decrypt2048")]
		public string Decrypt2048(string privateKeyRsa, string encryptedData)
		{
			var rsaDecrypt = new RsaDecrypt();
			var decryptedData = rsaDecrypt.Decrypt2048(privateKeyRsa, encryptedData);
			return decryptedData;
		}

		[HttpPost("Encrypt4096")]
		public string Encrypt4096(string publicKeyRsa, string dataToEncrypt)
		{
			var rsaEncrypt = new RsaEncrypt();
			var encryptedData = rsaEncrypt.Encrypt4096(publicKeyRsa, dataToEncrypt);
			return encryptedData;
		}

		[HttpPost("Decrypt4096")]
		public string Decrypt4096(string privateKeyRsa, string encryptedData)
		{
			var rsaDecrypt = new RsaDecrypt();
			var decryptedData = rsaDecrypt.Decrypt4096(privateKeyRsa, encryptedData);
			return decryptedData;
		}
	}
}
