using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Umbra.Core.Security;

/// <summary>Привязка данных к учётке ОС (для режима «без входа»).</summary>
public interface IDataProtector
{
    byte[] Protect(byte[] data);
    byte[] Unprotect(byte[] data);
}

/// <summary>Windows DPAPI (CryptProtectData). Расшифровать может только тот же пользователь Windows на том же ПК.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDpapi : IDataProtector
{
    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptProtectData(ref DataBlob dataIn, string? desc, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptUnprotectData(ref DataBlob dataIn, IntPtr desc, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);

    public byte[] Protect(byte[] data) => Run(data, protect: true);
    public byte[] Unprotect(byte[] data) => Run(data, protect: false);

    private static byte[] Run(byte[] data, bool protect)
    {
        var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            var input = new DataBlob { cbData = data.Length, pbData = handle.AddrOfPinnedObject() };
            bool ok = protect
                ? CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out var output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out output);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                var result = new byte[output.cbData];
                Marshal.Copy(output.pbData, result, 0, output.cbData);
                return result;
            }
            finally { LocalFree(output.pbData); }
        }
        finally { handle.Free(); }
    }
}

/// <summary>Только для тестов и не-Windows: НЕ защищает данные.</summary>
public sealed class NullProtector : IDataProtector
{
    public byte[] Protect(byte[] data) => (byte[])data.Clone();
    public byte[] Unprotect(byte[] data) => (byte[])data.Clone();
}
