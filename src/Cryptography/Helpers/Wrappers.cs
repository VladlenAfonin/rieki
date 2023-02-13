using System.Security.Cryptography;
using System.Text;
using Cryptography.Native;

namespace Cryptography.Helpers;

/// <summary>Wrappers of native calls.</summary>
public static class Wrappers
{
    /// <summary>
    /// Get list of cryptographic service providers available.
    /// </summary>
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

        while (Methods.CryptEnumProviders(
            provIndex,
            IntPtr.Zero,
            0,
            out var provType,
            null,
            ref encodedProvNameSize))
        {
            errorCode = Methods.GetLastError();
            if (errorCode != 0)
            {
                throw new CryptographicException(unchecked((int)errorCode));
            }

            encodedProvName = new byte[encodedProvNameSize];

            if (!Methods.CryptEnumProviders(
                provIndex++,
                IntPtr.Zero,
                0,
                out provType,
                encodedProvName,
                ref encodedProvNameSize))
            {
                errorCode = Methods.GetLastError();
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

        while (Methods.CryptEnumProviderTypes(
            provIndex,
            IntPtr.Zero,
            0,
            out var provType,
            null,
            ref encodedProvNameSize))
        {
            errorCode = Methods.GetLastError();
            if (errorCode != 0)
            {
                throw new CryptographicException(unchecked((int)errorCode));
            }

            encodedProvName = new byte[encodedProvNameSize];

            if (!Methods.CryptEnumProviderTypes(
                provIndex++,
                IntPtr.Zero,
                0,
                out provType,
                encodedProvName,
                ref encodedProvNameSize))
            {
                errorCode = Methods.GetLastError();
                throw new CryptographicException(unchecked((int)errorCode));
            }

            var provName = Encoding.ASCII.GetString(encodedProvName);

            yield return (provType, provName);
        }
    }
}
