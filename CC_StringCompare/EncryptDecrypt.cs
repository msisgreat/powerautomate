public class Script : ScriptBase
{
    private static readonly byte[] AesIVText = Encoding.UTF8.GetBytes("Thisisivtext9273");
    public override async Task<HttpResponseMessage> ExecuteAsync()
    {
        switch(this.Context.OperationId)
        {
            case "EncryptText":
                return await this.EncryptText().ConfigureAwait(false);
                break;
            case "DecryptText":
                return await this.DecryptText().ConfigureAwait(false);
                break;
            default:
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.BadRequest);
                response.Content = new StringContent("Unknown Operation");
                return response;
                break;
        }
    }

    private async Task<HttpResponseMessage> EncryptText()
    {
        var contentAsString = await this.Context.Request.Content.ReadAsStringAsync().ConfigureAwait(false);
        var contentAsJson = JObject.Parse(contentAsString);

        var plainText = (string)contentAsJson["TextToEncrypt"];
        var privateKey = Encoding.UTF8.GetBytes((string)contentAsJson["PrivateKey"]);
        string encrypted;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.KeySize = 256;
            aesAlg.Key = privateKey;
            aesAlg.IV = AesIVText;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    encrypted = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }
        HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Content = new StringContent(encrypted);// CreateJsonContent("{\"message\": \"Hello World\"}");
        return response;
    }

    private async Task<HttpResponseMessage> DecryptText()
    {
        var contentAsString = await this.Context.Request.Content.ReadAsStringAsync().ConfigureAwait(false);
        var contentAsJson = JObject.Parse(contentAsString);

        var encryptedText = (string)contentAsJson["TextToDecrypt"];
        var privateKey = Encoding.UTF8.GetBytes((string)contentAsJson["PrivateKey"]);
        string decrypted = null;

        using (Aes aesAlg = Aes.Create())
        {
        aesAlg.KeySize = 256; // Set the KeySize to 256 bits for AES-256
        aesAlg.Key = privateKey;
        aesAlg.IV = AesIVText;

        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedText)))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        decrypted = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
        response.Content = new StringContent(decrypted);// CreateJsonContent("{\"message\": \"Hello World\"}");
        return response;
    }
}
