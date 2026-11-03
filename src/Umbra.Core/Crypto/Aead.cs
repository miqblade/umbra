using System.Security.Cryptography;

namespace Umbra.Core.Crypto;

/// <summary>AES-256-GCM. Формат результата: шифртекст || тег(16) — как в Python-версии Umbra (cryptography.AESGCM).</summary>
public static class Aead
{
    public const int NonceSize = 12, TagSize = 16;

    public static byte[] Seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        var result = new byte[plaintext.Length + TagSize];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, result.AsSpan(0, plaintext.Length), result.AsSpan(plaintext.Length), aad);
        return result;
    }

    /// <summary>Возвращает null при неверном ключе или повреждённых данных.</summary>
    public static byte[]? Open(byte[] key, byte[] nonce, byte[] sealedData, byte[] aad)
    {
        if (sealedData.Length < TagSize) return null;
        int n = sealedData.Length - TagSize;
        var plain = new byte[n];
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            gcm.Decrypt(nonce, sealedData.AsSpan(0, n), sealedData.AsSpan(n), plain, aad);
            return plain;
        }
        catch (CryptographicException) { return null; }
    }
}
