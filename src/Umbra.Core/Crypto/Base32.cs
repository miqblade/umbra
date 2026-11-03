namespace Umbra.Core.Crypto;

/// <summary>Base32 (RFC 4648) для секретов аутентификатора. Регистр и «=» не важны.</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static byte[] Decode(string text)
    {
        var clean = new string(text.Where(c => c != '=' && !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        var output = new List<byte>(clean.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (char c in clean)
        {
            int val = Alphabet.IndexOf(c);
            if (val < 0) throw new FormatException("Недопустимый символ в секрете аутентификатора.");
            buffer = (buffer << 5) | val; bits += 5;
            if (bits >= 8) { bits -= 8; output.Add((byte)((buffer >> bits) & 0xFF)); }
        }
        return output.ToArray();
    }

    public static string Encode(byte[] data)
    {
        var sb = new System.Text.StringBuilder();
        int buffer = 0, bits = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b; bits += 8;
            while (bits >= 5) { bits -= 5; sb.Append(Alphabet[(buffer >> bits) & 31]); }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }
}
