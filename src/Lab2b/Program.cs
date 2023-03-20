using CommandLine;
using Lab2b.Actions;
using Lab2b.Options;

namespace Lab2b;

internal static class Program
{
    private static void Main(string[] args)
    {
        Parser.Default.ParseArguments<GenerateOptions>(args)
            .WithParsed<GenerateOptions>(options => new Generate(options).Do());
    }
}