using System;
using System.Security.Cryptography;
using System.Text;

namespace RIFS.Crypto.RSA
{
    public class RsaEncrypt
	{
        private const int KeySize2048Bits = 2048;
        private const int KeySize4096Bits = 4096;
        private readonly UnicodeEncoding _byteConverter;
        private string PublicKeyRsa { get; set; }
        private string EncryptedData { get; set; }

        public RsaEncrypt()
		{
            _byteConverter = new UnicodeEncoding();
            EncryptedData = string.Empty;
        }

        public string Encrypt2048(string publicKeyRsa, string dataToEncrypt)
        {
            try
            {
                using var rsa = new RSACryptoServiceProvider(KeySize2048Bits);
                PublicKeyRsa = publicKeyRsa;
                Encrypt(rsa, dataToEncrypt);
				rsa.Clear();
				return EncryptedData;
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

        public string Encrypt4096(string publicKeyRsa, string dataToEncrypt)
        {
            try
            {
				using var rsa = new RSACryptoServiceProvider(KeySize4096Bits);
                PublicKeyRsa = publicKeyRsa;
                Encrypt(rsa, dataToEncrypt);
				rsa.Clear();
				return EncryptedData;
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

        private void Encrypt(RSACryptoServiceProvider rsa, string dataToEncrypt) 
        {
            rsa.FromXmlString(PublicKeyRsa);
            var byteToEncrypt = _byteConverter.GetBytes(dataToEncrypt);
            var encryptedByte = rsa.Encrypt(byteToEncrypt, false);
            EncryptedData = Convert.ToBase64String(encryptedByte);
        }
    }
}
