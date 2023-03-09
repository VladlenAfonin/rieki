using System.Runtime.InteropServices;
using Cryptography.Models.Handles;

namespace Cryptography.Native;

internal static class NativeMethods
{
    private const string Advapi32 = "libcapi10";
    private const string Crypt32 = "libcapi20";
    private const string Kernel32 = "librdrsup";

    #region Advapi32

    [DllImport(
        Advapi32,
        SetLastError = true,
        CharSet = CharSet.Ansi,
        EntryPoint = "CryptAcquireContextA")]
    internal static extern bool CryptAcquireContext(
        out CspSafeHandle hProv,
        string? pszContainer,
        string? pszProvider,
        uint dwProvType,
        uint dwFlags);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptReleaseContext")]
    internal static extern bool CryptReleaseContext(
        IntPtr hProv,
        uint dwFlags);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptGetProvParam")]
    internal static extern bool CryptGetProvParam(
        CspSafeHandle hProv,
        uint dwParam,
        IntPtr pbData,
        ref uint pdwDataLen,
        uint dwFlags);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptEnumProvidersA")]
    internal static extern bool CryptEnumProviders(
        uint dwIndex,
        IntPtr pdwReserved,
        uint dwFlags,
        out uint pdwProvType,
        byte[]? szProvName,
        ref uint pcbProvName);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptEnumProviderTypesA")]
    internal static extern bool CryptEnumProviderTypes(
        uint dwIndex,
        IntPtr pdwReserved,
        uint dwFlags,
        out uint pdwProvType,
        byte[]? szProvName,
        ref uint pcbProvName);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptGetUserKey")]
    internal static extern bool CryptGetUserKey(
        CspSafeHandle hProv,
        uint dwKeySpec,
        out IntPtr phUserKey);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptGenKey")]
    internal static extern bool CryptGenKey(
        CspSafeHandle hProv,
        uint Algid,
        uint dwFlags,
        out IntPtr phKey);

    [DllImport(
       Advapi32,
       SetLastError = true,
       EntryPoint = "CryptDestroyKey")]
    internal static extern bool CryptDestroyKey(
        IntPtr hKey);

    #endregion Advapi32

    #region Kernel32

    [DllImport(
        Kernel32,
        EntryPoint = "GetLastError")]
    internal static extern uint GetLastError();

    #endregion Kernel32
}
