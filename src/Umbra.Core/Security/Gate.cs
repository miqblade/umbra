using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Umbra.Core.Crypto;

namespace Umbra.Core.Security;

public enum AuthMode { TwoFactor, PasswordOnly, None }

public enum LoginResult
{
    Success,
    BadPassword,
    BadCode,
    /// <summary>Исчерпаны попытки: вызывающий обязан уничтожить сейф (Vault.Destroy).</summary>
    WipeRequired,
}

/// <summary>Формат файла umbra.dat — совместим с Umbra 4.x на Python.</summary>
public sealed class GateData
{
    [JsonPropertyName("v")] public int Version { get; set; } = 1;
    [JsonPropertyName("mode")] public string Mode { get; set; } = "2fa";
    [JsonPropertyName("salt")] public string Salt { get; set; } = "";
    [JsonPropertyName("nonce")] public string Nonce { get; set; } = "";
    [JsonPropertyName("blob")] public string Blob { get; set; } = "";
    [JsonPropertyName("attempts")] public int Attempts { get; set; }
    [JsonPropertyName("recovery")] public List<string> Recovery { get; set; } = new();
    [JsonPropertyName("letter")] public string Letter { get; set; } = "";
    [JsonPropertyName("size_gb")] public int SizeGb { get; set; } = 30;
    [JsonPropertyName("autopw")] public string? AutoPassword { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>
/// Вход в Umbra: пароль (расшифровывает блок в umbra.dat), по желанию код аутентификатора, счётчик неверных попыток.
/// Режимы: 2fa — пароль+код; pw — только пароль; none — Umbra открывает сейф сама (пароль под защитой DPAPI).
/// </summary>
public sealed class Gate
{
    public const int MaxAttempts = 5;
    private static readonly byte[] Aad = Encoding.ASCII.GetBytes("umbra-gate");
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    private readonly string _path;
    private readonly IDataProtector _protector;
    private readonly Func<DateTimeOffset> _clock;
    private GateData _d;

    private Gate(string path, GateData data, IDataProtector protector, Func<DateTimeOffset> clock)
    { _path = path; _d = data; _protector = protector; _clock = clock; }

    public static bool Exists(string path) => File.Exists(path);

    public static Gate Open(string path, IDataProtector protector, Func<DateTimeOffset>? clock = null)
    {
        var data = JsonSerializer.Deserialize<GateData>(File.ReadAllText(path, Encoding.UTF8), Json)
                   ?? throw new InvalidDataException("umbra.dat пуст или повреждён.");
        return new Gate(path, data, protector, clock ?? (() => DateTimeOffset.UtcNow));
    }

    public static Gate Create(string path, IDataProtector protector, string password, AuthMode mode, string? totpSecret,
                              IEnumerable<string>? recoveryCodes, Func<DateTimeOffset>? clock = null)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var d = new GateData { Salt = Convert.ToBase64String(salt) };
        var gate = new Gate(path, d, protector, clock ?? (() => DateTimeOffset.UtcNow));
        gate.WriteBlob(password, totpSecret ?? "");
        d.Mode = ModeName(mode);
        d.Recovery = (recoveryCodes ?? Array.Empty<string>()).Select(c => HashRecovery(salt, c)).ToList();
        if (mode == AuthMode.None) d.AutoPassword = Convert.ToBase64String(protector.Protect(Encoding.UTF8.GetBytes(password)));
        gate.Save();
        return gate;
    }

    public AuthMode Mode => _d.Mode switch { "pw" => AuthMode.PasswordOnly, "none" => AuthMode.None, _ => AuthMode.TwoFactor };
    public int Attempts => _d.Attempts;
    public int AttemptsLeft => Math.Max(0, MaxAttempts - _d.Attempts);
    public int RecoveryLeft => _d.Recovery.Count;
    public string Letter { get => _d.Letter; set { _d.Letter = value; Save(); } }
    public int SizeGb { get => _d.SizeGb; set { _d.SizeGb = value; Save(); } }

    public static string ModeName(AuthMode m) => m switch { AuthMode.PasswordOnly => "pw", AuthMode.None => "none", _ => "2fa" };

    /// <summary>Пароль, сохранённый для режима «без входа» (только Windows-пользователь, который его сохранил). Иначе null.</summary>
    public string? AutoPassword()
    {
        if (string.IsNullOrEmpty(_d.AutoPassword)) return null;
        try { return Encoding.UTF8.GetString(_protector.Unprotect(Convert.FromBase64String(_d.AutoPassword))); }
        catch (Exception) { return null; }
    }

    /// <summary>Расшифровывает секрет аутентификатора паролем. null — пароль неверный.</summary>
    public string? OpenSecret(string password)
    {
        var key = Scrypt.DeriveKey(password, Convert.FromBase64String(_d.Salt));
        var raw = Aead.Open(key, Convert.FromBase64String(_d.Nonce), Convert.FromBase64String(_d.Blob), Aad);
        CryptographicOperations.ZeroMemory(key);
        if (raw == null) return null;
        using var doc = JsonDocument.Parse(raw);
        return doc.RootElement.TryGetProperty("totp", out var t) ? (t.GetString() ?? "") : "";
    }

    /// <summary>Единая точка входа. Считает попытки; на пятой подряд неудаче возвращает WipeRequired.</summary>
    public LoginResult Login(string password, string? code)
    {
        if (_d.Attempts >= MaxAttempts) return LoginResult.WipeRequired;
        var result = Check(password, code);
        if (result == LoginResult.Success) { if (_d.Attempts != 0) { _d.Attempts = 0; Save(); } return result; }
        _d.Attempts++;
        Save();
        return _d.Attempts >= MaxAttempts ? LoginResult.WipeRequired : result;
    }

    /// <summary>Режим «без входа»: открыть сейф сохранённым паролем (проверка пароля — расшифровка блока).</summary>
    public string? AutoLogin()
    {
        if (Mode != AuthMode.None) return null;
        var pw = AutoPassword();
        if (pw == null || OpenSecret(pw) == null) return null;
        if (_d.Attempts != 0) { _d.Attempts = 0; Save(); }
        return pw;
    }

    private LoginResult Check(string password, string? code)
    {
        var secret = OpenSecret(password);
        if (secret == null) return LoginResult.BadPassword;
        if (Mode != AuthMode.TwoFactor) return LoginResult.Success;
        var c = (code ?? "").Trim();
        var digits = c.Replace(" ", "");
        if (digits.Length == 6 && digits.All(char.IsAsciiDigit))
            return Totp.Verify(secret, digits, _clock()) ? LoginResult.Success : LoginResult.BadCode;
        var h = HashRecovery(Convert.FromBase64String(_d.Salt), c);
        if (_d.Recovery.Remove(h)) { Save(); return LoginResult.Success; }
        return LoginResult.BadCode;
    }

    /// <summary>Сменить способ входа. Пароль уже проверен вызывающим. secret/codes обязательны при включении 2fa с нуля.</summary>
    public void SetMode(AuthMode mode, string password, string? newSecret = null, IEnumerable<string>? newCodes = null)
    {
        var current = OpenSecret(password) ?? throw new UnauthorizedAccessException("Неверный пароль.");
        var secret = newSecret ?? current;
        if (mode == AuthMode.TwoFactor && string.IsNullOrEmpty(secret))
            throw new InvalidOperationException("Для режима «пароль + код» нужен секрет аутентификатора.");
        WriteBlob(password, secret);
        _d.Mode = ModeName(mode);
        if (newCodes != null) _d.Recovery = newCodes.Select(c => HashRecovery(Convert.FromBase64String(_d.Salt), c)).ToList();
        _d.AutoPassword = mode == AuthMode.None ? Convert.ToBase64String(_protector.Protect(Encoding.UTF8.GetBytes(password))) : null;
        Save();
    }

    public static IReadOnlyList<string> NewRecoveryCodes(int count = 8)
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        string Part() => new(Enumerable.Range(0, 4).Select(_ => alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]).ToArray());
        return Enumerable.Range(0, count).Select(_ => Part() + "-" + Part()).ToList();
    }

    public static string NormalizeRecovery(string code) => new(code.ToUpperInvariant().Where(c => (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')).ToArray());

    private static string HashRecovery(byte[] salt, string code)
        => Convert.ToHexString(SHA256.HashData(salt.Concat(Encoding.UTF8.GetBytes(NormalizeRecovery(code))).ToArray())).ToLowerInvariant();

    private void WriteBlob(string password, string secret)
    {
        var salt = Convert.FromBase64String(_d.Salt);
        var key = Scrypt.DeriveKey(password, salt);
        var nonce = RandomNumberGenerator.GetBytes(Aead.NonceSize);
        var payload = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Dictionary<string, object> { ["totp"] = secret, ["ok"] = 1 }));
        _d.Nonce = Convert.ToBase64String(nonce);
        _d.Blob = Convert.ToBase64String(Aead.Seal(key, nonce, payload, Aad));
        CryptographicOperations.ZeroMemory(key);
    }

    private void Save()
    {
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_d, Json), new UTF8Encoding(false));
        File.Move(tmp, _path, overwrite: true);
    }
}
