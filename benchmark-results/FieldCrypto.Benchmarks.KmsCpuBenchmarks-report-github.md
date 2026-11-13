```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.9711/25H2/2025Update/HudsonValley2)
13th Gen Intel Core i7-13620H 2.40GHz, 1 CPU, 16 logical and 10 physical cores
.NET SDK 10.0.401
  [Host]     : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
  DefaultJob : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3


```
| Method                             | Mean       | Error     | StdDev    | Gen0   | Allocated |
|----------------------------------- |-----------:|----------:|----------:|-------:|----------:|
| &#39;local KEK wrap&#39;                   |   1.295 μs | 0.0095 μs | 0.0089 μs | 0.0362 |     456 B |
| &#39;local KEK unwrap&#39;                 |   1.185 μs | 0.0238 μs | 0.0363 μs | 0.0305 |     392 B |
| &#39;OCI request signature (RSA-2048)&#39; | 939.752 μs | 4.8976 μs | 4.5812 μs |      - |    3088 B |
