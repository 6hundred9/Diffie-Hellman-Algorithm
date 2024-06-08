using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class Cryptography
{
    private static readonly int SaltSize = 16;
    private static readonly int KeySize = 32;
    private static readonly int Iterations = 1000;

    public static string Encrypt(string plaintext, string password)
    {
        byte[] salt = GenerateSalt();
        byte[] key = DeriveKey(password, salt);
        byte[] iv = GenerateIV();

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plaintext);
                    }
                }
                byte[] encrypted = ms.ToArray();
                byte[] result = new byte[salt.Length + iv.Length + encrypted.Length];
                Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                Buffer.BlockCopy(iv, 0, result, salt.Length, iv.Length);
                Buffer.BlockCopy(encrypted, 0, result, salt.Length + iv.Length, encrypted.Length);
                return Convert.ToBase64String(result);
            }
        }
    }

    public static string Decrypt(string ciphertext, string password)
    {
        byte[] fullCipher = Convert.FromBase64String(ciphertext);
        byte[] salt = new byte[SaltSize];
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[fullCipher.Length - salt.Length - iv.Length];

        Buffer.BlockCopy(fullCipher, 0, salt, 0, salt.Length);
        Buffer.BlockCopy(fullCipher, salt.Length, iv, 0, iv.Length);
        Buffer.BlockCopy(fullCipher, salt.Length + iv.Length, encrypted, 0, encrypted.Length);

        byte[] key = DeriveKey(password, salt);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(encrypted, 0, encrypted.Length);
                }
                byte[] decrypted = ms.ToArray();
                return Encoding.UTF8.GetString(decrypted);
            }
        }
    }

    private static byte[] GenerateSalt()
    {
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);
            return salt;
        }
    }

    private static byte[] GenerateIV()
    {
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            byte[] iv = new byte[16];
            rng.GetBytes(iv);
            return iv;
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, Iterations))
        {
            return keyDerivationFunction.GetBytes(KeySize);
        }
    }
}
