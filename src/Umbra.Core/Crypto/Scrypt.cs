using System.Security.Cryptography;

namespace Umbra.Core.Crypto;

/// <summary>scrypt (RFC 7914) на одной лишь стандартной библиотеке .NET. Параметры по умолчанию совпадают с Umbra 4.x (n=2^15, r=8, p=1).</summary>
public static class Scrypt
{
    public static byte[] DeriveKey(byte[] password, byte[] salt, int n = 1 << 15, int r = 8, int p = 1, int length = 32)
    {
        if (n < 2 || (n & (n - 1)) != 0) throw new ArgumentException("n должно быть степенью двойки", nameof(n));
        if (r < 1 || p < 1 || length < 1) throw new ArgumentException("r, p, length должны быть > 0");
        int blockBytes = 128 * r;
        byte[] b = Rfc2898DeriveBytes.Pbkdf2(password, salt, 1, HashAlgorithmName.SHA256, p * blockBytes);
        var x = new uint[32 * r];
        var v = new uint[32 * r * n];
        var scratch = new uint[32 * r];
        for (int i = 0; i < p; i++)
        {
            int off = i * blockBytes;
            for (int k = 0; k < x.Length; k++)
                x[k] = BitConverter.ToUInt32(b, off + 4 * k); // little-endian на всех поддерживаемых платформах
            RoMix(x, v, scratch, n, r);
            for (int k = 0; k < x.Length; k++)
                BitConverter.TryWriteBytes(b.AsSpan(off + 4 * k, 4), x[k]);
        }
        byte[] dk = Rfc2898DeriveBytes.Pbkdf2(password, b, 1, HashAlgorithmName.SHA256, length);
        Array.Clear(v); Array.Clear(x); Array.Clear(b);
        return dk;
    }

    public static byte[] DeriveKey(string password, byte[] salt, int n = 1 << 15, int r = 8, int p = 1, int length = 32)
        => DeriveKey(System.Text.Encoding.UTF8.GetBytes(password), salt, n, r, p, length);

    private static void RoMix(uint[] x, uint[] v, uint[] scratch, int n, int r)
    {
        int words = 32 * r;
        for (int i = 0; i < n; i++)
        {
            Array.Copy(x, 0, v, i * words, words);
            BlockMix(x, scratch, r);
        }
        for (int i = 0; i < n; i++)
        {
            int j = (int)(x[(2 * r - 1) * 16] & (uint)(n - 1));
            int baseIdx = j * words;
            for (int k = 0; k < words; k++) x[k] ^= v[baseIdx + k];
            BlockMix(x, scratch, r);
        }
    }

    private static void BlockMix(uint[] b, uint[] y, int r)
    {
        Span<uint> t = stackalloc uint[16];
        for (int k = 0; k < 16; k++) t[k] = b[(2 * r - 1) * 16 + k];
        for (int i = 0; i < 2 * r; i++)
        {
            for (int k = 0; k < 16; k++) t[k] ^= b[i * 16 + k];
            Salsa20_8(t);
            int dst = (i % 2 == 0 ? i / 2 : r + i / 2) * 16;
            for (int k = 0; k < 16; k++) y[dst + k] = t[k];
        }
        Array.Copy(y, b, 32 * r);
    }

    private static uint Rotl(uint a, int b) => (a << b) | (a >> (32 - b));

    private static void Salsa20_8(Span<uint> b)
    {
        Span<uint> x = stackalloc uint[16];
        b.CopyTo(x);
        for (int i = 0; i < 8; i += 2)
        {
            x[4] ^= Rotl(x[0] + x[12], 7); x[8] ^= Rotl(x[4] + x[0], 9);
            x[12] ^= Rotl(x[8] + x[4], 13); x[0] ^= Rotl(x[12] + x[8], 18);
            x[9] ^= Rotl(x[5] + x[1], 7); x[13] ^= Rotl(x[9] + x[5], 9);
            x[1] ^= Rotl(x[13] + x[9], 13); x[5] ^= Rotl(x[1] + x[13], 18);
            x[14] ^= Rotl(x[10] + x[6], 7); x[2] ^= Rotl(x[14] + x[10], 9);
            x[6] ^= Rotl(x[2] + x[14], 13); x[10] ^= Rotl(x[6] + x[2], 18);
            x[3] ^= Rotl(x[15] + x[11], 7); x[7] ^= Rotl(x[3] + x[15], 9);
            x[11] ^= Rotl(x[7] + x[3], 13); x[15] ^= Rotl(x[11] + x[7], 18);
            x[1] ^= Rotl(x[0] + x[3], 7); x[2] ^= Rotl(x[1] + x[0], 9);
            x[3] ^= Rotl(x[2] + x[1], 13); x[0] ^= Rotl(x[3] + x[2], 18);
            x[6] ^= Rotl(x[5] + x[4], 7); x[7] ^= Rotl(x[6] + x[5], 9);
            x[4] ^= Rotl(x[7] + x[6], 13); x[5] ^= Rotl(x[4] + x[7], 18);
            x[11] ^= Rotl(x[10] + x[9], 7); x[8] ^= Rotl(x[11] + x[10], 9);
            x[9] ^= Rotl(x[8] + x[11], 13); x[10] ^= Rotl(x[9] + x[8], 18);
            x[12] ^= Rotl(x[15] + x[14], 7); x[13] ^= Rotl(x[12] + x[15], 9);
            x[14] ^= Rotl(x[13] + x[12], 13); x[15] ^= Rotl(x[14] + x[13], 18);
        }
        for (int i = 0; i < 16; i++) b[i] += x[i];
    }
}
