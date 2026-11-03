using System.Text.Json;
using System.Text.RegularExpressions;

namespace Umbra.Core.Modules;

public sealed class ModuleCommand
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    /// <summary>Аргументы запуска; поддерживаются подстановки {profile} и {workspace}.</summary>
    public List<string> Args { get; set; } = new();
}

/// <summary>
/// Описание модуля Umbra (файл module.json). Через модули добавляется собственный софт: SEO-инструменты, парсеры, проверки.
/// kind=process — запуск программы в окружении выбранного профиля (его сеть, его IP);
/// kind=web — локальная страница внутри Umbra; kind=native — встроенная библиотека .NET.
/// </summary>
public sealed class ModuleManifest
{
    public static readonly string[] KnownPermissions = { "network:profile", "fs:workspace", "fs:downloads", "clipboard:write" };
    private static readonly Regex IdRule = new(@"^[a-z0-9]+([.\-][a-z0-9]+)*$", RegexOptions.Compiled);
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Version { get; set; } = "0.1.0";
    public string Kind { get; set; } = "process";
    public string Entry { get; set; } = "";
    public List<string> Permissions { get; set; } = new();
    public List<ModuleCommand> Commands { get; set; } = new();

    public static ModuleManifest Parse(string json)
    {
        var m = JsonSerializer.Deserialize<ModuleManifest>(json, Options) ?? throw new InvalidDataException("Пустой module.json");
        m.Validate();
        return m;
    }

    public void Validate()
    {
        if (!IdRule.IsMatch(Id) || Id.Length > 64) throw new InvalidDataException($"Недопустимый id модуля: «{Id}».");
        if (string.IsNullOrWhiteSpace(Title)) throw new InvalidDataException($"У модуля {Id} нет названия.");
        if (Kind is not ("process" or "web" or "native")) throw new InvalidDataException($"Неизвестный тип модуля: {Kind}.");
        if (Entry.Length == 0 || Path.IsPathRooted(Entry) || Regex.IsMatch(Entry, @"^([A-Za-z]:|[/\\])") || Entry.Split('/', '\\').Contains(".."))
            throw new InvalidDataException($"Точка входа модуля {Id} должна быть относительной и внутри папки модуля.");
        var bad = Permissions.Except(KnownPermissions).ToList();
        if (bad.Count > 0) throw new InvalidDataException($"Неизвестные разрешения: {string.Join(", ", bad)}.");
        if (Commands.Select(c => c.Id).Distinct().Count() != Commands.Count) throw new InvalidDataException("Повторяющиеся команды.");
    }
}
