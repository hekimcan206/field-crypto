using System.Globalization;
using BenchmarkDotNet.Running;
using FieldCrypto.Benchmarks;

// dotnet run -c Release --project benchmarks/FieldCrypto.Benchmarks -- micro [BenchmarkDotNet args]
// dotnet run -c Release --project benchmarks/FieldCrypto.Benchmarks -- macro [patients] [runs]
CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

if (args.Length > 0 && args[0] == "macro")
{
    var patients = args.Length > 1 ? int.Parse(args[1], CultureInfo.InvariantCulture) : 10_000;
    var runs = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 3;
    var results = await new MacroBenchmarks(patients, runs, Console.Out).RunAsync();
    Directory.CreateDirectory("benchmark-results");
    var path = Path.Combine("benchmark-results", $"macro-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
    await File.WriteAllTextAsync(path, MacroBenchmarks.ToJson(results));
    Console.WriteLine();
    Console.WriteLine($"results written to {path}");
    return;
}

BenchmarkSwitcher.FromTypes([typeof(FieldBenchmarks), typeof(KmsCpuBenchmarks)]).Run(args.Length > 0 && args[0] == "micro" ? args[1..] : args);
