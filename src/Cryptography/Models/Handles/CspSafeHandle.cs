using Cryptography.Native;
using Microsoft.Win32.SafeHandles;

namespace Cryptography.Models.Handles;

public class CspSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public CspSafeHandle()
        : base(true)
    {
    }

    protected override bool ReleaseHandle()
    {
        return NativeMethods.CryptReleaseContext(this.handle, 0);
    }
}
