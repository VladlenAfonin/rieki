using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cryptography.Native;

public static class NativeMethods
{
    private const string Advapi32 = "libcapi10";
    private const string Crypt32 = "libcapi20";
    private const string Kernel32 = "librdrsup";

    #region Advapi32

    [DllImport(
        Advapi32,
        SetLastError = true,
        CharSet = CharSet.Ansi,
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
        EntryPoint = "CryptGetProvParam")]
    public static extern bool CryptGetProvParam(
        IntPtr hProv,
        uint dwParam,
        byte[]? pbData,
        ref uint pdwDataLen,
        uint dwFlags);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptGetProvParam")]
    public static extern bool CryptGetProvParam(
        IntPtr hProv,
        uint dwParam,
        IntPtr pbData,
        ref uint pdwDataLen,
        uint dwFlags);

    [DllImport(
        Advapi32,
        SetLastError = true,
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
        EntryPoint = "CryptEnumProviderTypesA")]
    public static extern bool CryptEnumProviderTypes(
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
    public static extern bool CryptGetUserKey(
        IntPtr hProv,
        uint dwKeySpec,
        out IntPtr phUserKey);

    [DllImport(
        Advapi32,
        SetLastError = true,
        EntryPoint = "CryptGenKey")]
    public static extern bool CryptGenKey(
        IntPtr hProv,
        uint Algid,
        uint dwFlags,
        out IntPtr phKey);

    [DllImport(
       Advapi32,
       SetLastError = true,
       EntryPoint = "CryptDestroyKey")]
    public static extern bool CryptDestroyKey(
        IntPtr hKey);

    #endregion Advapi32

    #region Kernel32

    [DllImport(
        Kernel32,
        EntryPoint = "GetLastError")]
    public static extern uint GetLastError();

    #endregion Kernel32
}
