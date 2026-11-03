using System.Text.Json.Serialization;

namespace Umbra.Core.Model;

public enum NetworkMode { Blocked, Direct, WireGuard, OpenVpn, Proxy }

/// <summary>Сетевое окружение профиля/программы. Выбирается пользователем явно; по умолчанию трафик заблокирован.</summary>
public sealed class NetworkPolicy
{
    public NetworkMode Mode { get; set; } = NetworkMode.Blocked;
    /// <summary>Имя сохранённого VPN-конфига внутри сейфа (WireGuard .conf / .ovpn).</summary>
    public string? ConfigName { get; set; }
    /// <summary>Для Proxy: socks5://host:port.</summary>
    public string? ProxyUrl { get; set; }
    /// <summary>Если туннель упал — не пускать трафик (всегда true; поле нужно как явное намерение в данных).</summary>
    public bool KillSwitch { get; set; } = true;
}

public sealed class Profile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name { get; set; } = "";
    public string Color { get; set; } = "#7c6cff";
    public string Notes { get; set; } = "";
    public NetworkPolicy Network { get; set; } = new();
    /// <summary>Язык браузера профиля (например ru, uk, en-US) — пустое значение = по умолчанию.</summary>
    public string Lang { get; set; } = "";
}

public sealed class WorkspaceConfig
{
    public int Version { get; set; } = 1;
    public List<Profile> Profiles { get; set; } = new();
    /// <summary>Идентификаторы включённых модулей.</summary>
    public List<string> EnabledModules { get; set; } = new();
}
