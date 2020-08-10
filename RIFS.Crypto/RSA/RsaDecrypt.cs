using System;
using System.Security.Cryptography;
using System.Text;

namespace RIFS.Crypto.RSA
{
	public class RsaDecrypt
	{
		private const int KeySize2048Bits = 2048;
		private const int KeySize4096Bits = 4096;
		private readonly UnicodeEncoding _byteConverter;
		private string PrivateKeyRsa { get; set; }
		private string DecryptedData { get; set; }

		public RsaDecrypt()
		{
			_byteConverter = new UnicodeEncoding();
			DecryptedData = string.Empty;
		}

        public string Decrypt2048(string privateKeyRsa, string encryptedData)
        {
            try
            {
				using var rsa = new RSACryptoServiceProvider(KeySize2048Bits);
				PrivateKeyRsa = privateKeyRsa;
				Decrypt(rsa, encryptedData);
				rsa.Clear();
				return DecryptedData;
			}
            catch (CryptographicException cryptographicException)
            {
                throw cryptographicException;
            }
            catch (Exception exception)
            {
                throw exception;
            }
        }

		public string Decrypt4096(string privateKeyRsa, string encryptedData)
		{
			try
			{
				using var rsa = new RSACryptoServiceProvider(KeySize4096Bits);
				PrivateKeyRsa = privateKeyRsa;
				Decrypt(rsa, encryptedData);
				rsa.Clear();
				return DecryptedData;
			}
			catch (CryptographicException cryptographicException)
			{
				throw cryptographicException;
			}
			catch (Exception exception)
			{
				throw exception;
			}
		}

		private void Decrypt(RSACryptoServiceProvider rsa, string encryptedData)
        {
			rsa.FromXmlString(PrivateKeyRsa);

			var encryptedByte = Convert.FromBase64String(encryptedData);
			var decryptedByte = rsa.Decrypt(encryptedByte, false);
			DecryptedData = _byteConverter.GetString(decryptedByte);
		}
    }
}
