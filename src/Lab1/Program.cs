using CommandLine;
using Cryptography.Helpers;

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
            .WithParsed<ListOptions>(
                o =>
                {
                    if (!string.IsNullOrWhiteSpace(o.provName))
                    {
                        // TODO: Print available algorithms.
                    }
                    else if (o.provType == 0)
                    {
                        var csps = Wrappers.CryptEnumProviderTypes();

                        foreach (var (provType, provName) in csps)
                        {
                            Console.WriteLine($"{provType}\t{provName}");
                        }
                    }
                    else
                    {
                        var csps = Wrappers.CryptEnumProviders();

                        foreach (var (provType, provName) in csps)
                        {
                            if (provType == o.provType)
                            {
                                Console.WriteLine($"{provType}\t{provName}");
                            }
                        }
                    }
                });
    }
}

