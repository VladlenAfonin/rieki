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
        public uint provType { get; set; }

        [Option(
            'n',
            "name",
            Default = null,
            Required = false,
            HelpText = "List available algorithms for chosen provider.")]
        public string? provName { get; set; }
    }

    static void Main(string[] args)
    {
        Parser.Default.ParseArguments<ListOptions>(args)
            .WithParsed<ListOptions>(options => RunList(options));
    }

    private static void RunList(ListOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.provName))
        {
            if (options.provType == 0)
            {
                Console.Error.WriteLine("No provider type specified.");
                Environment.Exit(1);
            }

            var csps = Methods.CryptEnumProviders();

            var (provType, provName) = csps.FirstOrDefault(
                csp =>
                    csp.Item1 == options.provType &&
                    csp.Item2.Contains(options.provName));

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
        else if (options.provType == 0)
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
                if (provType == options.provType)
                {
                    Console.WriteLine($"{provType}\t{provName}");
                }
            }
        }
    }
}