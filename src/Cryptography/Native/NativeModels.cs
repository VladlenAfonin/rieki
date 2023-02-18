using System.Runtime.InteropServices;

namespace Cryptography.Native;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
internal struct PROV_ENUMALGS
{
    internal uint aiAlgid;
    internal uint dwBitLen;
    internal uint dwNameLen;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
    internal string szName;
}