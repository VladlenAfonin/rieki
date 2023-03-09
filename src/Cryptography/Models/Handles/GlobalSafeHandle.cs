using System.Runtime.InteropServices;

namespace Cryptography.Models.Handles;

public class GlobalSafeHandle : SafeHandle
{
    public GlobalSafeHandle(int sizeBytes)
    {
        var handle = Marshal.AllocHGlobal(sizeBytes);
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(handle);
        return true;
    }
}

