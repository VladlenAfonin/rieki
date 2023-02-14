using System.Runtime.InteropServices;

namespace Cryptography.Native;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct PROV_ENUMALGS
{
    public uint aiAlgid;
    public uint dwBitLen;
    public uint dwNameLen;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
    public string szName;
}