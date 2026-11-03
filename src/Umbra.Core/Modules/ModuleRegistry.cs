namespace Umbra.Core.Modules;

public sealed record LoadedModule(ModuleManifest Manifest, string Directory);

public sealed class ModuleRegistry
{
    private readonly List<LoadedModule> _modules = new();
    private readonly List<string> _errors = new();

    public IReadOnlyList<LoadedModule> Modules => _modules;
    public IReadOnlyList<string> Errors => _errors;

    /// <summary>Читает все папки вида {root}/{имя}/module.json. Сломанный модуль не мешает остальным — ошибка попадает в Errors.</summary>
    public static ModuleRegistry Discover(string root)
    {
        var reg = new ModuleRegistry();
        if (!Directory.Exists(root)) return reg;
        foreach (var dir in Directory.EnumerateDirectories(root).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            var file = Path.Combine(dir, "module.json");
            if (!File.Exists(file)) continue;
            try
            {
                var m = ModuleManifest.Parse(File.ReadAllText(file));
                var entry = Path.GetFullPath(Path.Combine(dir, m.Entry));
                if (!entry.StartsWith(Path.GetFullPath(dir) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                    throw new InvalidDataException("Точка входа выходит за пределы папки модуля.");
                if (reg._modules.Any(x => x.Manifest.Id == m.Id)) throw new InvalidDataException($"Повторный id {m.Id}.");
                reg._modules.Add(new LoadedModule(m, dir));
            }
            catch (Exception e) when (e is InvalidDataException or System.Text.Json.JsonException or IOException)
            {
                reg._errors.Add($"{Path.GetFileName(dir)}: {e.Message}");
            }
        }
        return reg;
    }
}
