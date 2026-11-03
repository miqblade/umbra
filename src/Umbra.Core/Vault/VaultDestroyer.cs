using System.Security.Cryptography;

namespace Umbra.Core.Vault;

/// <summary>Необратимое уничтожение контейнера VeraCrypt: затирает заголовки (в начале и в конце файла) случайными данными и удаляет файл.</summary>
public static class VaultDestroyer
{
    private const int HeaderZone = 128 * 1024; // основной заголовок + скрытый, затем их копии в конце

    public static void Destroy(string containerPath)
    {
        if (!File.Exists(containerPath)) return;
        long length = new FileInfo(containerPath).Length;
        using (var fs = new FileStream(containerPath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            Overwrite(fs, 0, (int)Math.Min(HeaderZone, length));
            if (length > HeaderZone) Overwrite(fs, length - Math.Min(HeaderZone, length), (int)Math.Min(HeaderZone, length));
            fs.Flush(true);
        }
        File.Delete(containerPath);
    }

    private static void Overwrite(FileStream fs, long offset, int count)
    {
        var junk = RandomNumberGenerator.GetBytes(count);
        fs.Position = offset;
        fs.Write(junk, 0, count);
    }
}
