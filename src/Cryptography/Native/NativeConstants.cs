namespace Cryptography.Native;

public static class NativeConstants
{
    public const uint PP_NAME = 0x00000004;
    public const uint PP_PROVTYPE = 0x00000010;
    public const uint PP_ENUMALGS = 0x00000001;
    
    public const uint CRYPT_FIRST = 0x00000001;
    public const uint CRYPT_NEXT = 0x00000002;
    public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
    public const uint CRYPT_NEWKEYSET = 0x00000008;
    public const uint CRYPT_DELETEKEYSET = 0x00000016;
    
    public const uint CRYPT_EXPORTABLE = 0x00000001;
    
    public const uint AT_KEYEXCHANGE = 0x00000001;
    public const uint AT_SIGNATURE = 0x00000002;
    
    public const uint ERROR_NO_MORE_ITEMS = 0x00000103;
}