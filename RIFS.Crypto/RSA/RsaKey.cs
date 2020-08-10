using System.Security.Cryptography;

namespace RIFS.Crypto.RSA
{
	public class RsaKey
	{
		public RsaKey()
		{
			GenerateKeys();
		}

		public string PublicKey { get; private set; }
		public string PrivateKey { get; private set; }

		private void GenerateKeys() 
		{
			using var rsa = new RSACryptoServiceProvider();
			//var rsaParameters = rsa.ExportParameters(false);
			PublicKey = rsa.ToXmlString(false);
			PrivateKey = rsa.ToXmlString(true);
			rsa.Clear();
		} 
	}
}
