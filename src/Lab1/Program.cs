using CommandLine;
using Cryptography.Wrappers;

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
        HelpText = "List elements. By default lists available cryptographic " +
            "service provider types.")]
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

    static void Main(string[] args)
    {
        Parser.Default.ParseArguments<ListOptions, CreateOptions>(args)
            .WithParsed<ListOptions>(options => RunList(options))
            .WithParsed<CreateOptions>(options => RunCreate(options));
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

            var csps = Methods.CryptEnumProviders();

            var (provType, provName) = csps.FirstOrDefault(
                csp =>
                    csp.Item1 == options.ProvType &&
                    csp.Item2.Contains(options.ProvName));

            if ((provType, provName) == default)
            {
                Environment.Exit(1);
            }

            Console.WriteLine($"{provType}\t{provName}\n");

            var algs = Methods.EnumAlgInfos(provType, provName);
            foreach (var alg in algs)
            {
                Console.WriteLine($"{alg.AlgId}\t{alg.BitLen}\t{alg.Name}");
            }
        }
        else if (options.ProvType == 0)
        {
            var csps = Methods.CryptEnumProviderTypes();

            foreach (var (provType, provName) in csps)
            {
                Console.WriteLine($"{provType}\t{provName}");
            }
        }
        else
        {
            var csps = Methods.CryptEnumProviders();

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
        var csps = Methods.CryptEnumProviders();

        var (provType, provName) = csps.FirstOrDefault(
                csp =>
                    csp.Item1 == options.ProvType &&
                    csp.Item2.Contains(options.ProvName!));

        if ((provType, provName) == default)
        {
            Environment.Exit(1);
        }

        Methods.CreateKeyContainer(
            provType,
            provName,
            options.ContainerName!,
            options.AlgId);

        Console.WriteLine("Key container created.");
    }
}