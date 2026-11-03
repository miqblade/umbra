using System.Security.Cryptography;

namespace Umbra.Core.Crypto;

/// <summary>TOTP по RFC 6238 (HMAC-SHA1, 30 секунд, 6 цифр) — совместим с Google Authenticator.</summary>
public static class Totp
{
    public static string Code(string base32Secret, DateTimeOffset time, int step = 30, int digits = 6)
    {
        byte[] key = Base32.Decode(base32Secret);
        long counter = time.ToUnixTimeSeconds() / step;
        Span<byte> msg = stackalloc byte[8];
        for (int i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xFF); counter >>= 8; }
        byte[] h = HMACSHA1.HashData(key, msg);
        int o = h[^1] & 0x0F;
        int bin = ((h[o] & 0x7F) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
        int mod = 1;
        for (int i = 0; i < digits; i++) mod *= 10;
        return (bin % mod).ToString().PadLeft(digits, '0');
    }

    /// <summary>Принимает код текущего и соседних интервалов (±30 с на расхождение часов).</summary>
    public static bool Verify(string base32Secret, string code, DateTimeOffset now)
    {
        var given = System.Text.Encoding.ASCII.GetBytes(code);
        bool ok = false;
        foreach (int d in new[] { -1, 0, 1 })
        {
            var expected = System.Text.Encoding.ASCII.GetBytes(Code(base32Secret, now.AddSeconds(30 * d)));
            ok |= CryptographicOperations.FixedTimeEquals(expected, given);
        }
        return ok;
    }

    public static string NewSecret() => Base32.Encode(RandomNumberGenerator.GetBytes(20));

    public static string ProvisioningUri(string secret, string account, string issuer = "Umbra")
        => $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";
}
