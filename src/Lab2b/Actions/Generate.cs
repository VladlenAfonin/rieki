using System.Security.Cryptography;
using Lab2b.Options;

namespace Lab2b.Actions;

public class Generate
{
    private readonly GenerateOptions _options;

    public Generate(GenerateOptions options)
    {
        _options = options;
    }

    public void Do()
    {
        var cspParameters = new CspParameters();
        cspParameters.KeyContainerName = _options.ContainerName;
        
        using var rsa = new RSACryptoServiceProvider(cspParameters);
        
        File.WriteAllBytes(_options.ContainerName, rsa.ExportSubjectPublicKeyInfo());
    }
}