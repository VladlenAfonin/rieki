using System.Runtime.InteropServices;
using System.Text;
using Cryptography.Models;
using Cryptography.Models.Handles;
using Cryptography.Native;

namespace Cryptography;

/// <summary>Utility methods.</summary>
public static class Utilities
{
    /// <summary>Enumerate cryptographic service providers available.</summary>
    /// <returns>List of tuples (provType, provName).</returns>
    /// <exception cref="InvalidOperationException">
    /// Error occured during native operation.
    /// </exception>
    public static IEnumerable<CspInfo> CryptEnumProviders()
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
                NativeError.Throw(
                    errorCode,
                    nameof(NativeMethods.CryptEnumProviders));
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
                NativeError.Throw(nameof(NativeMethods.CryptGetProvParam));
            }

            var provName = Encoding.ASCII.GetString(encodedProvName);

            yield return new CspInfo(provType, provName);
        }
    }

    /// <summary>
    /// Get dictionary (provType -> provName) of cryptographic service
    /// providers available.
    /// </summary>
    /// <returns>Dictionary (provType -> provName).</returns>
    /// <exception cref="InvalidOperationException">
    /// Error occured during native operation.
    /// </exception>
    public static IEnumerable<CspInfo> CryptEnumProviderTypes()
    {
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
                NativeError.Throw(
                    errorCode,
                    nameof(NativeMethods.CryptEnumProviderTypes));
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
                NativeError.Throw(nameof(NativeMethods.CryptGetProvParam));
            }

            var provName = Encoding.ASCII.GetString(encodedProvName);

            yield return new CspInfo(provType, provName);
        }
    }
}
