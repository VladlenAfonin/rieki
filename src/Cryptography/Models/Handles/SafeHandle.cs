using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Cryptography.Models.Handles;

public abstract class SafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeHandle()
        : base(true)
    {
    }

    public static implicit operator IntPtr(SafeHandle safeHandle) =>
        safeHandle.handle;
}
