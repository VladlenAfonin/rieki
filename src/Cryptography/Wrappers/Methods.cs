using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Cryptography.Native;

namespace Cryptography.Wrappers;

/// <summary>Wrappers of native calls.</summary>
public static class Methods
{
    /// <summary>Enumerate cryptographic service providers available.</summary>
    /// <returns>List of tuples (provType, provName).</returns>
    /// <exception cref="CryptographicException">
    /// Error occured during native operation.
    /// </exception>
    public static IEnumerable<(uint, string)> CryptEnumProviders()
    {
        byte[] encodedProvName;
        uint encodedProvNameSize = 0;
        uint errorCode = 0;
        uint provIndex = 0;

        while (NativeMethods.CryptEnumProviders(
            provIndex,
            IntPtr.Zero,
            0,
            out var provType,
            null,
            ref encodedProvNameSize))
        {
            errorCode = NativeMethods.GetLastError();
            if (errorCode != 0)
            {
                throw new CryptographicException(unchecked((int)errorCode));
            }

            encodedProvName = new byte[encodedProvNameSize];

            if (!NativeMethods.CryptEnumProviders(
                provIndex++,
                IntPtr.Zero,
                0,
                out provType,
                encodedProvName,
                ref encodedProvNameSize))
            {
                errorCode = NativeMethods.GetLastError();
                throw new CryptographicException(unchecked((int)errorCode));
            }

            var provName = Encoding.ASCII.GetString(encodedProvName);

            yield return (provType, provName);
        }
    }

    /// <summary>
    /// Get dictionary (provType -> provName) of cryptographic service
    /// providers available.
    /// </summary>
    /// <returns>Dictionary (provType -> provName).</returns>
    /// <exception cref="CryptographicException">
    /// Error occured during native operation.
    /// </exception>
    public static IEnumerable<(uint, string)> CryptEnumProviderTypes()
    {
        var csps = new Dictionary<uint, string>();

        byte[] encodedProvName;
        uint encodedProvNameSize = 0;
        uint errorCode = 0;
        uint provIndex = 0;

        while (NativeMethods.CryptEnumProviderTypes(
            provIndex,
            IntPtr.Zero,
            0,
            out var provType,
            null,
            ref encodedProvNameSize))
        {
            errorCode = NativeMethods.GetLastError();
            if (errorCode != 0)
            {
                throw new CryptographicException(unchecked((int)errorCode));
            }

            encodedProvName = new byte[encodedProvNameSize];

            if (!NativeMethods.CryptEnumProviderTypes(
                provIndex++,
                IntPtr.Zero,
                0,
                out provType,
                encodedProvName,
                ref encodedProvNameSize))
            {
                errorCode = NativeMethods.GetLastError();
                throw new CryptographicException(unchecked((int)errorCode));
            }

            var provName = Encoding.ASCII.GetString(encodedProvName);

            yield return (provType, provName);
        }
    }

    /// <summary>Enumerate available algorightms for given provider.</summary>
    /// <param name="provType">Provider type.</param>
    /// <param name="provName">Provider name.</param>
    /// <returns>Algorithms enumerator.</returns>
    /// <exception cref="CryptographicException">
    /// Error occured during native operation.
    /// </exception>
    public static IEnumerable<AlgInfo> EnumAlgInfos(
        uint provType,
        string provName)
    {
        if (!NativeMethods.CryptAcquireContext(
            out var hProv,
            null,
            provName,
            provType,
            NativeConstants.CRYPT_VERIFYCONTEXT))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }

        var algInfoSize = 0u;
        IntPtr algInfoPtr = IntPtr.Zero;

        if (!NativeMethods.CryptGetProvParam(
            hProv,
            NativeConstants.PP_ENUMALGS,
            null,
            ref algInfoSize,
            NativeConstants.CRYPT_FIRST))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }

        algInfoPtr = Marshal.AllocHGlobal((int)algInfoSize);

        if (!NativeMethods.CryptGetProvParam(
            hProv,
            NativeConstants.PP_ENUMALGS,
            algInfoPtr,
            ref algInfoSize,
            NativeConstants.CRYPT_FIRST))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }

        var algInfoStruct = Marshal.PtrToStructure<PROV_ENUMALGS>(algInfoPtr);

        var algInfo = new AlgInfo
        {
            AlgId = algInfoStruct.aiAlgid,
            BitLen = algInfoStruct.dwBitLen,
            Name = algInfoStruct.szName,
        };

        Marshal.FreeHGlobal(algInfoPtr);

        yield return algInfo;

        while (NativeMethods.CryptGetProvParam(
            hProv,
            NativeConstants.PP_ENUMALGS,
            null,
            ref algInfoSize,
            NativeConstants.CRYPT_NEXT))
        {
            algInfoPtr = Marshal.AllocHGlobal((int)algInfoSize);

            if (!NativeMethods.CryptGetProvParam(
                hProv,
                NativeConstants.PP_ENUMALGS,
                algInfoPtr,
                ref algInfoSize,
                NativeConstants.CRYPT_NEXT))
            {
                var errorCode = NativeMethods.GetLastError();
                throw new CryptographicException(unchecked((int)errorCode));
            }

            algInfoStruct = Marshal.PtrToStructure<PROV_ENUMALGS>(algInfoPtr);

            algInfo = new AlgInfo
            {
                AlgId = algInfoStruct.aiAlgid,
                BitLen = algInfoStruct.dwBitLen,
                Name = algInfoStruct.szName,
            };

            Marshal.FreeHGlobal(algInfoPtr);

            yield return algInfo;
        }

        if (!NativeMethods.CryptReleaseContext(hProv, 0))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }
    }

    /// <summary>Create key container.</summary>
    /// <param name="provType">Provider type.</param>
    /// <param name="provName">Provider name.</param>
    /// <param name="containerName">Container name.</param>
    /// <param name="algId">
    /// Algorithm identifier. Should be either 1 or 2.
    /// </param>
    /// <exception cref="CryptographicException">
    /// Error occured during native operation
    /// </exception>
    /// <remarks>Key is created with EXPORTABLE flag.</remarks>
    public static void CreateKeyContainer(
        uint provType,
        string provName,
        string containerName,
        uint algId)
    {
        if (!NativeMethods.CryptAcquireContext(
            out var hProv,
            containerName,
            provName,
            provType,
            NativeConstants.CRYPT_NEWKEYSET))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }

        if (!NativeMethods.CryptGenKey(
            hProv,
            algId,
            NativeConstants.CRYPT_EXPORTABLE,
            out var hKey))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }

        if (!NativeMethods.CryptDestroyKey(hKey))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }

        if (!NativeMethods.CryptReleaseContext(hProv, 0))
        {
            var errorCode = NativeMethods.GetLastError();
            throw new CryptographicException(unchecked((int)errorCode));
        }
    }
}
