using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cryptography.Native;

public static class Methods
{
    private const string Advapi32 = "libcapi10";
    private const string Crypt32 = "libcapi20";
    private const string Kernel32 = "librdrsup";

    #region Advapi32

    [DllImport(
        Advapi32,
        SetLastError = true,
        CharSet = CharSet.Unicode,
        EntryPoint = "CryptAcquireContextA")
        ]
    public static extern bool CryptAcquireContext(
        out IntPtr hProv,
        string? pszContainer,
        string? pszProvider,
        uint dwProvType,
        uint dwFlags);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptReleaseContext")]
    public static extern bool CryptReleaseContext(
        IntPtr hProv,
        uint dwFlags);

    [DllImport(
        Advapi32,
        SetLastError = true,
        CharSet = CharSet.Unicode,
        EntryPoint = "CryptEnumProvidersA")]
    public static extern bool CryptEnumProviders(
        uint dwIndex,
        IntPtr pdwReserved,
        uint dwFlags,
        out uint pdwProvType,
        byte[]? szProvName,
        ref uint pcbProvName);

    [DllImport(
        Advapi32,
        SetLastError = true,
        CharSet = CharSet.Unicode,
        EntryPoint = "CryptEnumProviderTypesA")]
    public static extern bool CryptEnumProviderTypes(
        uint dwIndex,
        IntPtr pdwReserved,
        uint dwFlags,
        out uint pdwProvType,
        byte[]? szProvName,
        ref uint pcbProvName);

    #endregion Advapi32

    #region Kernel32

    [DllImport(
        Kernel32,
        EntryPoint = "GetLastError")]
    public static extern uint GetLastError();

    #endregion Kernel32
}
