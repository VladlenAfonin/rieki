using Cryptography.Native;

namespace Cryptography.Models;

public static class NativeError
{
    public static void Throw()
    {
        var errorCode = NativeMethods.GetLastError();
        throw new InvalidOperationException(
            $"0x{unchecked((int)errorCode):x}");
    }

    public static void Throw(uint errorCode)
    {
        throw new InvalidOperationException(
            $"0x{unchecked((int)errorCode):x}");
    }

    public static void Throw(string methodName)
    {
        var errorCode = NativeMethods.GetLastError();
        throw new InvalidOperationException(
            $"{methodName}: 0x{unchecked((int)errorCode):x}");
    }

    public static void Throw(uint errorCode, string methodName)
    {
        throw new InvalidOperationException(
            $"{methodName}: 0x{unchecked((int)errorCode):x}");
    }

}

