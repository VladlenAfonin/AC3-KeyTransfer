using System.Security.Cryptography;

namespace KeyTransfer.Common.Cryptography;

public static class Utilities
{
    public static byte[] Encrypt(byte[] data, byte[] key)
    {
        byte[] encryptedData;

        using var aes = Aes.Create();

        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using (var aesEncryptor = aes.CreateEncryptor())
        using (var memoryStream = new MemoryStream())
        {
            using (var cryptoStream = new CryptoStream(
                memoryStream, aesEncryptor, CryptoStreamMode.Write))
                cryptoStream.Write(data);

            encryptedData = memoryStream.ToArray();
        }

        return encryptedData;
    }

    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        byte[] unencryptedData;

        using var aes = Aes.Create();

        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using (var aesDecryptor = aes.CreateDecryptor())
        using (var memoryStream = new MemoryStream(data))
        {
            using (var cryptoStream = new CryptoStream(
                memoryStream, aesDecryptor, CryptoStreamMode.Read))
                cryptoStream.Read(data);

            unencryptedData = memoryStream.ToArray();
        }

        return unencryptedData;
    }
}
