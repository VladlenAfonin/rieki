using System;
namespace Cryptography.Models.Exceptions;

public class CspNotFoundException : Exception
{
    public CspNotFoundException(uint provType, string? provName = null)
        : base($"CSP not found with type {provType}" +
            $"{(provName is null ? "" : " and name " + provName)}.")
    {
    }
}
