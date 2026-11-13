```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.9711/25H2/2025Update/HudsonValley2)
13th Gen Intel Core i7-13620H 2.40GHz, 1 CPU, 16 logical and 10 physical cores
.NET SDK 10.0.401
  [Host]     : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
  DefaultJob : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3


```
| Method                                | Mean       | Error    | StdDev   | Gen0   | Allocated |
|-------------------------------------- |-----------:|---------:|---------:|-------:|----------:|
| &#39;encrypt 11-char national id&#39;         | 1,391.5 ns | 27.76 ns | 70.65 ns | 0.0267 |     336 B |
| &#39;decrypt 11-char national id&#39;         | 1,181.8 ns | 23.36 ns | 41.52 ns | 0.0210 |     272 B |
| &#39;encrypt 1 KiB note (row-bound)&#39;      | 2,199.9 ns | 42.16 ns | 43.29 ns | 0.1888 |    2376 B |
| &#39;decrypt 1 KiB note (row-bound)&#39;      | 1,850.7 ns | 15.67 ns | 13.89 ns | 0.2632 |    3320 B |
| &#39;blind index, digits (16 bits)&#39;       |   491.1 ns |  2.56 ns |  2.14 ns | 0.0153 |     192 B |
| &#39;blind index, Turkish fold (12 bits)&#39; |   604.1 ns |  4.87 ns |  4.32 ns | 0.0134 |     168 B |
