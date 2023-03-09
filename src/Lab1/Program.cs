using CommandLine;
using Cryptography;
using Cryptography.Models;
using Cryptography.Native;

namespace Lab1;

class Program
{
    [Verb(
        "list",
        HelpText = "List elements. By default lists available cryptographic " +
            "service provider types.")]
    public class ListOptions
    {
        [Option(
            't',
            "type",
            Default = (uint)0,
            Required = false,
            HelpText = "List registered cryptographic service providers for " +
                "chosen provider type.")]
        public uint ProvType { get; set; }

        [Option(
            'n',
            "name",
            Default = null,
            Required = false,
            HelpText = "List available algorithms for chosen provider.")]
        public string? ProvName { get; set; }
    }

    [Verb(
        "create",
        HelpText = "Create key container.")]
    public class CreateOptions
    {
        [Option(
            't',
            "type",
            Default = (uint)0,
            Required = true,
            HelpText = "Cryptographic service providers type.")]
        public uint ProvType { get; set; }

        [Option(
            'n',
            "name",
            Default = null,
            Required = true,
            HelpText = "Cryptographic service provider name.")]
        public string? ProvName { get; set; }

        [Option(
            'c',
            "container-name",
            Default = null,
            Required = true,
            HelpText = "Key container name.")]
        public string? ContainerName { get; set; }

        [Option(
            'a',
            "algid",
            Default = null,
            Required = true,
            HelpText = "Algorithm identifier. Should be 1 (AT_KEYEXCHANGE) " +
                "or 2 (AT_SIGNATURE).")]
        public uint AlgId { get; set; }
    }

    [Verb(
        "destroy",
        HelpText = "Destroy key container.")]
    public class DestroyOptions
    {
        [Option(
            't',
            "type",
            Default = (uint)0,
            Required = true,
            HelpText = "Cryptographic service providers type.")]
        public uint ProvType { get; set; }

        [Option(
            'n',
            "name",
            Default = null,
            Required = true,
            HelpText = "Cryptographic service provider name.")]
        public string? ProvName { get; set; }

        [Option(
            'c',
            "container-name",
            Default = null,
            Required = true,
            HelpText = "Key container name.")]
        public string? ContainerName { get; set; }
    }

    static void Main(string[] args)
    {
        Parser.Default.ParseArguments<ListOptions, CreateOptions, DestroyOptions>(args)
            .WithParsed<ListOptions>(options => RunList(options))
            .WithParsed<CreateOptions>(options => RunCreate(options))
            .WithParsed<DestroyOptions>(options => RunDestroy(options));
    }

    private static void RunList(ListOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.ProvName))
        {
            if (options.ProvType == 0)
            {
                Console.Error.WriteLine("No provider type specified.");
                Environment.Exit(1);
            }

            using var csp = new Csp(options.ProvType, options.ProvName);

            Console.WriteLine($"{options.ProvType}\t{csp.Name}\n");

            foreach (var alg in csp.Algorithms)
            {
                Console.WriteLine($"{alg.AlgId}\t{alg.BitLen}\t{alg.Name}");
            }
        }
        else if (options.ProvType == 0)
        {
            var csps = Utilities.CryptEnumProviderTypes();

            foreach (var (provType, provName) in csps)
            {
                Console.WriteLine($"{provType}\t{provName}");
            }
        }
        else
        {
            var csps = Utilities.CryptEnumProviders();

            foreach (var (provType, provName) in csps)
            {
                if (provType == options.ProvType)
                {
                    Console.WriteLine($"{provType}\t{provName}");
                }
            }
        }
    }

    private static void RunCreate(CreateOptions options)
    {
        using var csp = new Csp(
            provType: options.ProvType,
            provNameLike: options.ProvName!,
            containerName: options.ContainerName!,
            flags: NativeConstants.CRYPT_NEWKEYSET);

        csp.GenerateKey(options.AlgId);

        Console.WriteLine("Key container created.");
    }

    private static void RunDestroy(DestroyOptions options)
    {
        using var csp = new Csp(
            provType: options.ProvType,
            provNameLike: options.ProvName!,
            containerName: options.ContainerName!);

        csp.DestroyKeyContainer();

        Console.WriteLine("Key container destroyed.");
    }
}