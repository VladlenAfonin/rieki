namespace Cryptography.Wrappers;

/// <summary>Wrapper over PROV_ENUMALGS.</summary>
public struct AlgInfo
{
    public uint AlgId;
    public uint BitLen;
    public string Name;
}