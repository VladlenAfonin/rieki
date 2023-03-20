using CommandLine;

namespace Lab2b.Options;

[Verb("generate", HelpText = "Generate exchange keypair.")]
public class GenerateOptions
{
    [Option('n', "filename", HelpText = "Export file name.")]
    public string ContainerName { get; init; }
}