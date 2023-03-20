using System.Runtime.InteropServices;
using Cryptography.Models.Exceptions;
using Cryptography.Models.Handles;
using Cryptography.Native;

namespace Cryptography.Models;

public sealed class Csp : IDisposable
{
	private CspSafeHandle _handle;

    public uint Type { get; init; }
    public string? Name { get; init; }
    public string? ContainerName { get; init; }
    public uint Flags { get; init; }
    public IEnumerable<Algorithm> Algorithms
    {
        get
        {
            var algInfoSize = 0u;
            IntPtr algInfoPtr = IntPtr.Zero;

            if (!NativeMethods.CryptGetProvParam(
                _handle,
                NativeConstants.PP_ENUMALGS,
                IntPtr.Zero,
                ref algInfoSize,
                NativeConstants.CRYPT_FIRST))
            {
                NativeError.Throw(nameof(NativeMethods.CryptGetProvParam));
            }

            algInfoPtr = Marshal.AllocHGlobal((int)algInfoSize);

            if (!NativeMethods.CryptGetProvParam(
                _handle,
                NativeConstants.PP_ENUMALGS,
                algInfoPtr,
                ref algInfoSize,
                NativeConstants.CRYPT_FIRST))
            {
                NativeError.Throw(nameof(NativeMethods.CryptGetProvParam));
            }

            var algInfoStruct = Marshal.PtrToStructure<PROV_ENUMALGS>(
                algInfoPtr);

            var algInfo = new Algorithm(
                algInfoStruct.aiAlgid,
                algInfoStruct.dwBitLen,
                algInfoStruct.szName);

            Marshal.FreeHGlobal(algInfoPtr);

            yield return algInfo;

            while (NativeMethods.CryptGetProvParam(
                _handle,
                NativeConstants.PP_ENUMALGS,
                IntPtr.Zero,
                ref algInfoSize,
                NativeConstants.CRYPT_NEXT))
            {
                algInfoPtr = Marshal.AllocHGlobal((int)algInfoSize);

                if (!NativeMethods.CryptGetProvParam(
                    _handle,
                    NativeConstants.PP_ENUMALGS,
                    algInfoPtr,
                    ref algInfoSize,
                    NativeConstants.CRYPT_NEXT))
                {
                    NativeError.Throw(nameof(NativeMethods.CryptGetProvParam));
                }

                algInfoStruct = Marshal.PtrToStructure<PROV_ENUMALGS>(
                    algInfoPtr);

                algInfo = new Algorithm(
                    algInfoStruct.aiAlgid,
                    algInfoStruct.dwBitLen,
                    algInfoStruct.szName);

                Marshal.FreeHGlobal(algInfoPtr);

                yield return algInfo;
            }
        }
    }

    public Csp(
        uint provType,
        string? provNameLike = null,
        string? containerName = null,
        uint flags = NativeConstants.CRYPT_VERIFYCONTEXT)
    {
        provNameLike = provNameLike?.Trim();

        var (found, fullProvName) = Find(provType, provNameLike);
        if (!found)
        {
            throw new CspNotFoundException(provType, provNameLike);
        }

        Name = fullProvName;
        Type = provType;
        ContainerName = containerName;

        if (!NativeMethods.CryptAcquireContext(
            out _handle,
            ContainerName,
            Name,
            Type,
            flags))
        {
            NativeError.Throw(nameof(NativeMethods.CryptAcquireContext));
        }
    }

    /// <summary>Destroy key container.</summary>
    /// <exception cref="InvalidOperationException">
    /// Error occured during native operation
    /// </exception>
    public void DestroyKeyContainer()
    {
        if (!NativeMethods.CryptAcquireContext(
            out var _,
            ContainerName,
            Name,
            Type,
            NativeConstants.CRYPT_DELETEKEYSET))
        {
            NativeError.Throw(nameof(NativeMethods.CryptAcquireContext));
        }
    }

    /// <summary>Create key container.</summary>
    /// <param name="algId">
    /// Algorithm identifier. Should be either 1 or 2.
    /// </param>
    /// <exception cref="InvalidOperationException">
    /// Error occured during native operation
    /// </exception>
    /// <remarks>Key is created with EXPORTABLE flag.</remarks>
    public void GenerateKey(uint algId)
    {
        if (!NativeMethods.CryptGenKey(
            _handle,
            algId,
            NativeConstants.CRYPT_EXPORTABLE,
            out var hKey))
        {
            NativeError.Throw(nameof(NativeMethods.CryptGenKey));
        }

        if (!NativeMethods.CryptDestroyKey(hKey))
        {
            NativeError.Throw(nameof(NativeMethods.CryptDestroyKey));
        }
    }


    public CspSafeHandle GetHandle() => _handle;

    public void Dispose()
    {
        _handle.Dispose();
    }

    private static bool Exists(uint provType)
    {
        var csps = Utilities.CryptEnumProviders();
        return csps.Select(csp => csp.ProvType).Contains(provType);
    }

    private static bool Exists(uint provType, string? provName)
    {
        var csps = Utilities.CryptEnumProviders();

        var cspInfoFound = csps.FirstOrDefault(
            csp =>
                csp.ProvType == provType &&
                (csp.ProvName?.Contains(provName ?? "") ?? true));

        return cspInfoFound is not null;
    }

    private static (bool, string?) Find(uint provType, string? provName)
    {
        var csps = Utilities.CryptEnumProviders();

        if (provName is null)
        {
            return (Exists(provType), null);
        }

        var cspInfoFound = csps.FirstOrDefault(
            csp =>
                csp.ProvType == provType &&
                csp.ProvName!.Contains(provName));

        if (cspInfoFound is null)
        {
            return (false, null);
        }

        return (true, cspInfoFound.ProvName!);
    }
}