using RIFS.Crypto.RSA;

namespace RIFS.Crypto.Entity
{
    static class Constants
    {
        public const string privateKeyRsa = "<RSAKeyValue><Modulus>0G1VJf3EqZV3u6k9BjtosNWZ3smDRjvkfQxRQymn5lVVw/EuVosJe+pSeMh0c7Nk/j42ZRYI/Ji8XDZsT6rVfMl+5uS1CPKKxZJJ6s1Vbjr+gv+R7+55W6EagPRxNvCQ5iPG8cfQQAfiFr0P9M4/hTtc0A2KI8Dn439gtBL19O4bJ5H9SlWC+z1/8QUnsehDFELUYYLsLpy3WFsphtK1Rql/0B3kEBdL2+JCNyBURr+BV1ZL6tsUODSZg0FfKfcCJ7043bYA+plTpjPsToQImkBYxl/xi7zc0CeuZP6BfUDXx2wE2hhI6UsGzRJTUzXz5avo4FSWyXokvyk/uOJCZQ==</Modulus><Exponent>AQAB</Exponent><P>9Pn5JbvaCUZXvS12oTB6zmjDklhfCjCE6hKdL1O+CymrKfF/3R5oPQQSm5nnSv7MDrbxS9BKTwVEOfYh/805JNeykogZG+/dNZT5y/gceo7+IaS5L7yg7RFTTNf584P2uxV2+EU6FjsEf3D3OsOzV4jcNllBYHKKibX5uGllRRM=</P><Q>2c5TZdxBImDbU3jdAhM1851YTtiy/9l+ex/XFfCScDPfACIjDGL00MzFZw5oubP714RtB/84Ztw4ra+NugdnSnhsLwEgGn2bfUQWI1sHbDOSJ+CeaZbdsLAiuSz3nnTyKLLIqy3ba0dEtfH6aoqZ94sbay4whEUK/j9W4QeCYac=</Q><DP>qx8OJYiR5panZTMjwbbOoe5WZpyqTsDTp3o3KD8T6lJCCPtz+K5r2+tDYEPiZ+WR/tlVtkKaFZa1MNO4rinZt92gFHFTMMudtvcIgq0en5HQ/QlGfo0B0Hegu3XGWI8ew1JcF1KsH6k8HBV57SeU2Bl20dQJMejw0v81n9ancdc=</DP><DQ>ihIiihri63Es+DBRIgSdme5v0aPLbScp59FaXt0fZ6NqRUJep3Z/rXFx3g+jUb2H86pOF9ixn3sRLwFvvbL9xpaqNe3ntQNVM0abJhSJkwzqJP9eTJ9Hr78oc+zOmBOYgzY6wVETnGEUbKaV0T5FtkfnvL0OIntGKcBrScGh5Fc=</DQ><InverseQ>G3AU8wzuhJwHDNwIEcm3ZqaWNkPE3nm06GIPvm4z0O1xphND9HWKdhRbMbzl77Ta9yzOsFYoq+/s60gHoqc19t5Tk9/GzfDBgQW7g80lPJlecR0Szg/lCVO7T8ZXyZ0v0AvZTXKTm8NRycX16w+MXY1D5i93yeeNup8G1ArLdiM=</InverseQ><D>wR0sEaFJAB9+6p9p7UZKP94JTUTEnuSLVdl9yY7lBCL47i2e04zLYsa/Vy3TyAflgTO/TnXWKcSScZXzUPVmDNLdA63QltOzBFAAsM9DYnjCrDmDzBzW0LE6T1UtOMw4VSO9BvQt3cXwE0VlbVtTu2w/GH4TCgGIWV8CCJaw0RfHw1YifBJWK4Xni/tiSoSezLAGD1HoFiUA2iFOSNlEMt1XoOUJFgk1xyDdtsMHmH+IdaeReDSuZAabhEGYQLOQJruqsNtXCN+8XZYEphxx/tgfqg/DPYle/4xYB3a0zZh4eGt0a+9FNgmXMI/K7L1pSOuSV6bjenSpWNOlbXejmQ==</D></RSAKeyValue>";
        public const string publicKeyRsa = "<RSAKeyValue><Modulus>0G1VJf3EqZV3u6k9BjtosNWZ3smDRjvkfQxRQymn5lVVw/EuVosJe+pSeMh0c7Nk/j42ZRYI/Ji8XDZsT6rVfMl+5uS1CPKKxZJJ6s1Vbjr+gv+R7+55W6EagPRxNvCQ5iPG8cfQQAfiFr0P9M4/hTtc0A2KI8Dn439gtBL19O4bJ5H9SlWC+z1/8QUnsehDFELUYYLsLpy3WFsphtK1Rql/0B3kEBdL2+JCNyBURr+BV1ZL6tsUODSZg0FfKfcCJ7043bYA+plTpjPsToQImkBYxl/xi7zc0CeuZP6BfUDXx2wE2hhI6UsGzRJTUzXz5avo4FSWyXokvyk/uOJCZQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
    }

    public class SecurityText2048
    {
        private string _value;

        public string Value
        {
            get => _value;
            set
            {
                if (string.IsNullOrEmpty(_value))
                {
                    var rsaEncrypt = new RsaEncrypt();
                    _value = rsaEncrypt.Encrypt2048(Constants.publicKeyRsa, value);
                }
            }
        }

        public string Decrypt()
        {
            var rsaDecrypt = new RsaDecrypt();
            return rsaDecrypt.Decrypt2048(Constants.privateKeyRsa, Value);
        }

        public SecurityText2048()
        {

        }

        public SecurityText2048(string value)
        {
            Value = value;
        }
    }
}
