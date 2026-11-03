namespace Umbra.Core.Vault;

/// <summary>Аргументы командной строки VeraCrypt. Пароль подставляется в момент запуска; в журналы идёт только Redacted().</summary>
public sealed record VeraCryptCommand(string Executable, IReadOnlyList<string> Args, int PasswordIndex)
{
    public string Redacted() => Executable + " " + string.Join(" ", Args.Select((a, i) => i == PasswordIndex ? "***" : a));
}

public static class VeraCryptArgs
{
    public static VeraCryptCommand Mount(string veraCryptExe, string container, char letter, string password, string label = "Umbra")
    {
        var a = new List<string> { "/v", container, "/l", char.ToUpperInvariant(letter).ToString(), "/p", password,
                                   "/q", "/s", "/c", "n", "/m", "label=" + label };
        return new(veraCryptExe, a, a.IndexOf(password, 5));
    }

    public static VeraCryptCommand Dismount(string veraCryptExe, char letter, bool force)
    {
        var a = new List<string> { "/d", char.ToUpperInvariant(letter).ToString(), "/q", "/s" };
        if (force) a.Add("/f");
        return new(veraCryptExe, a, -1);
    }

    public static VeraCryptCommand Create(string formatExe, string container, long sizeBytes, string password)
    {
        var a = new List<string> { "/create", container, "/size", sizeBytes.ToString(), "/password", password,
                                   "/hash", "sha512", "/encryption", "AES", "/filesystem", "NTFS", "/silent", "/force" };
        return new(formatExe, a, 5);
    }
}
