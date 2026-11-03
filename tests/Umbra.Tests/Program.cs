using System.Text;
using System.Text.Json;
using Umbra.Core.Crypto;
using Umbra.Core.Modules;
using Umbra.Core.Security;
using Umbra.Core.Vault;

// Лёгкий собственный раннер (без пакетов): код возврата != 0, если хоть одна проверка упала.
int passed = 0, failed = 0;
void Check(string name, Action test)
{
    try { test(); passed++; Console.WriteLine("  ok   " + name); }
    catch (Exception e) { failed++; Console.WriteLine("  FAIL " + name + " -> " + e.Message); }
}
void True(bool cond, string msg = "условие ложно") { if (!cond) throw new Exception(msg); }
void Eq<T>(T expected, T actual) { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"ожидалось {expected}, получено {actual}"); }
string Tmp() { var d = Path.Combine(Path.GetTempPath(), "umbra-test-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(d); return d; }

Console.WriteLine("Криптография");
Check("scrypt RFC 7914 вектор 1 (пустой пароль)", () => Eq(
    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    Convert.ToHexString(Scrypt.DeriveKey(Array.Empty<byte>(), Array.Empty<byte>(), 16, 1, 1, 64)).ToLowerInvariant()));
Check("scrypt RFC 7914 вектор 2 (password/NaCl, p=16)", () => Eq(
    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    Convert.ToHexString(Scrypt.DeriveKey(Encoding.ASCII.GetBytes("password"), Encoding.ASCII.GetBytes("NaCl"), 1024, 8, 16, 64)).ToLowerInvariant()));
Check("scrypt RFC 7914 вектор 3 (n=16384)", () => Eq(
    "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    Convert.ToHexString(Scrypt.DeriveKey(Encoding.ASCII.GetBytes("pleaseletmein"), Encoding.ASCII.GetBytes("SodiumChloride"), 16384, 8, 1, 64)).ToLowerInvariant()));
Check("TOTP RFC 6238 (SHA-1, 8 цифр)", () =>
{
    var s = Base32.Encode(Encoding.ASCII.GetBytes("12345678901234567890"));
    foreach (var (t, code) in new (long, string)[] { (59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130") })
        Eq(code, Totp.Code(s, DateTimeOffset.FromUnixTimeSeconds(t), 30, 8));
});
Check("TOTP: допускается соседний интервал, дальний — нет", () =>
{
    var s = Totp.NewSecret(); var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    True(Totp.Verify(s, Totp.Code(s, now.AddSeconds(-30)), now)); True(Totp.Verify(s, Totp.Code(s, now), now));
    True(!Totp.Verify(s, Totp.Code(s, now.AddSeconds(-90)), now));
});
Check("AES-GCM: круг, неверный ключ, подмена", () =>
{
    var key = new byte[32]; var nonce = new byte[12]; var aad = new byte[] { 1 };
    var sealedData = Aead.Seal(key, nonce, Encoding.UTF8.GetBytes("секрет"), aad);
    Eq("секрет", Encoding.UTF8.GetString(Aead.Open(key, nonce, sealedData, aad)!));
    True(Aead.Open(new byte[32].Select(_ => (byte)7).ToArray(), nonce, sealedData, aad) == null, "неверный ключ принят");
    sealedData[0] ^= 1; True(Aead.Open(key, nonce, sealedData, aad) == null, "подмена не замечена");
});

Console.WriteLine("Вход (Gate)");
var protector = new NullProtector();
Check("совместимость с umbra.dat, созданным Python-версией", () =>
{
    var dir = Tmp(); var dat = Path.Combine(dir, "umbra.dat");
    File.Copy(Path.Combine(AppContext.BaseDirectory, "fixtures", "umbra_py.dat"), dat);
    using var ex = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "umbra_py.expect.json")));
    var r = ex.RootElement; var pw = r.GetProperty("password").GetString()!; var time = DateTimeOffset.FromUnixTimeSeconds(r.GetProperty("time").GetInt64());
    var gate = Gate.Open(dat, protector, () => time);
    Eq(AuthMode.TwoFactor, gate.Mode);
    Eq(r.GetProperty("secret").GetString(), gate.OpenSecret(pw));
    Eq(LoginResult.Success, gate.Login(pw, r.GetProperty("code").GetString()));
    Eq(LoginResult.Success, gate.Login(pw, r.GetProperty("codes")[0].GetString()!.ToLowerInvariant().Replace("-", " ")));
    Eq(LoginResult.BadCode, gate.Login(pw, r.GetProperty("codes")[0].GetString()!)); // резервный код одноразовый
    True(File.ReadAllText(dat).Contains("custom_field"), "неизвестные поля файла потеряны при сохранении");
});
Check("создание и вход: пароль+код, 5 неверных = WipeRequired", () =>
{
    var dat = Path.Combine(Tmp(), "umbra.dat"); var t = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000); var secret = Totp.NewSecret();
    var g = Gate.Create(dat, protector, "пароль-123", AuthMode.TwoFactor, secret, Gate.NewRecoveryCodes(2), () => t);
    Eq(LoginResult.BadPassword, g.Login("нет", "000000")); Eq(LoginResult.BadCode, g.Login("пароль-123", "000000"));
    Eq(3, g.AttemptsLeft);
    Eq(LoginResult.Success, g.Login("пароль-123", Totp.Code(secret, t))); Eq(0, g.Attempts);
    for (int i = 0; i < 4; i++) Eq(LoginResult.BadPassword, g.Login("x", "000000"));
    Eq(LoginResult.WipeRequired, g.Login("x", "000000"));
    Eq(LoginResult.WipeRequired, g.Login("пароль-123", Totp.Code(secret, t))); // даже верные данные уже не принимаются
    Eq(LoginResult.WipeRequired, Gate.Open(dat, protector, () => t).Login("пароль-123", Totp.Code(secret, t))); // счётчик сохранён на диске
});
Check("режим «только пароль»", () =>
{
    var dat = Path.Combine(Tmp(), "umbra.dat"); var g = Gate.Create(dat, protector, "pw-pw-pw-1", AuthMode.PasswordOnly, null, null);
    Eq(LoginResult.Success, g.Login("pw-pw-pw-1", null)); Eq(LoginResult.BadPassword, g.Login("другой", null));
});
Check("режим «без входа» и переключение режимов", () =>
{
    var dat = Path.Combine(Tmp(), "umbra.dat"); var secret = Totp.NewSecret();
    var g = Gate.Create(dat, protector, "pw-pw-pw-1", AuthMode.TwoFactor, secret, Gate.NewRecoveryCodes(1));
    g.SetMode(AuthMode.None, "pw-pw-pw-1"); Eq(AuthMode.None, g.Mode); Eq("pw-pw-pw-1", g.AutoLogin());
    g.SetMode(AuthMode.TwoFactor, "pw-pw-pw-1"); Eq(secret, g.OpenSecret("pw-pw-pw-1")); True(g.AutoLogin() == null);
    True(!File.ReadAllText(dat).Contains("autopw"), "пароль остался в файле после выхода из режима «без входа»");
    True(Throws(() => g.SetMode(AuthMode.None, "неверный")) is UnauthorizedAccessException, "смена режима с неверным паролем прошла");
});
Exception? Throws(Action a) { try { a(); return null; } catch (Exception e) { return e; } }
Check("режим 2fa нельзя включить без секрета", () =>
{
    var g = Gate.Create(Path.Combine(Tmp(), "umbra.dat"), protector, "pw-pw-pw-1", AuthMode.PasswordOnly, null, null);
    True(Throws(() => g.SetMode(AuthMode.TwoFactor, "pw-pw-pw-1")) is InvalidOperationException);
});

Console.WriteLine("Сейф");
Check("уничтожение контейнера: файл удалён", () =>
{
    var f = Path.Combine(Tmp(), "Umbra.hc"); File.WriteAllBytes(f, new byte[500_000]); VaultDestroyer.Destroy(f); True(!File.Exists(f));
});
Check("аргументы VeraCrypt: пароль скрыт в журнале", () =>
{
    var c = VeraCryptArgs.Mount("VeraCrypt.exe", @"D:\Umbra.hc", 'u', "СЕКРЕТ");
    True(!c.Redacted().Contains("СЕКРЕТ")); True(c.Args.Contains("СЕКРЕТ")); Eq("U", c.Args[3]);
});

Console.WriteLine("Модули");
Check("корректный module.json принимается", () =>
{
    var m = ModuleManifest.Parse("""{"id":"seo.page-check","title":"Проверка страницы","kind":"process","entry":"run.exe","permissions":["network:profile"],"commands":[{"id":"check","title":"Проверить","args":["{profile}"]}]}""");
    Eq("seo.page-check", m.Id);
});
Check("опасные module.json отклоняются", () =>
{
    foreach (var bad in new[] { """{"id":"A B","title":"x","entry":"a"}""", """{"id":"ok","title":"x","entry":"..\\evil.exe"}""", """{"id":"ok","title":"x","entry":"C:\\evil.exe"}""",
                                """{"id":"ok","title":"x","entry":"a","permissions":["root"]}""", """{"id":"ok","title":"x","kind":"magic","entry":"a"}""" })
        True(Throws(() => ModuleManifest.Parse(bad)) is InvalidDataException, "принято: " + bad);
});
Check("реестр модулей: сломанный модуль не мешает остальным", () =>
{
    var root = Tmp(); Directory.CreateDirectory(Path.Combine(root, "a")); Directory.CreateDirectory(Path.Combine(root, "b"));
    File.WriteAllText(Path.Combine(root, "a", "module.json"), """{"id":"good","title":"Хороший","entry":"x.exe"}""");
    File.WriteAllText(Path.Combine(root, "b", "module.json"), """{"id":"bad id","title":"Плохой","entry":"x.exe"}""");
    var reg = ModuleRegistry.Discover(root); Eq(1, reg.Modules.Count); Eq(1, reg.Errors.Count);
});

Console.WriteLine($"\nИтог: прошло {passed}, упало {failed}");
return failed == 0 ? 0 : 1;
