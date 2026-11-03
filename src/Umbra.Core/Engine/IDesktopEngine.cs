using Umbra.Core.Model;

namespace Umbra.Core.Engine;

public enum EngineState { Stopped, Starting, Running, Failed }

public sealed record LaunchRequest(string ProfileId, string AppId, IReadOnlyList<string> Args);

public sealed record LaunchResult(bool Started, string Message);

/// <summary>
/// «Движок рабочего стола»: где физически выполняются браузеры и программы профилей.
/// Реализации (планируются): WslEngine (WSL2+WSLg, сетевые пространства Linux, GPU), VmEngine (QEMU), позже — другие.
/// Ядро Umbra не зависит от конкретного движка.
/// </summary>
public interface IDesktopEngine
{
    string Name { get; }
    EngineState State { get; }
    Task StartAsync(CancellationToken ct);
    Task StopAsync(bool force, CancellationToken ct);
    /// <summary>Применить сетевую политику профиля (поднять туннель, правила kill-switch).</summary>
    Task ApplyNetworkAsync(Profile profile, CancellationToken ct);
    Task<LaunchResult> LaunchAsync(LaunchRequest request, CancellationToken ct);
    Task CloseProfileAsync(string profileId, bool force, CancellationToken ct);
    /// <summary>Внешний IP, который реально видит профиль (проверка изнутри его сетевого окружения). null — недоступно.</summary>
    Task<string?> ProbeIpAsync(string profileId, CancellationToken ct);
}
