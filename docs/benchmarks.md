# Benchmarks

Every number here was measured on the machine below; raw output is in [`benchmark-results/`](../benchmark-results).
Nothing is extrapolated. Where a number would need hardware or services this project does not have (a real OCI
tenancy, a dedicated database server), it is not given.

## Environment

| | |
|---|---|
| CPU | Intel Core i7-13620H (10 cores, 16 threads), laptop |
| RAM | 15.7 GB host; Docker Desktop VM 7.6 GB (WSL2, kernel 6.18) |
| OS | Windows 11 25H2 |
| .NET | SDK 10.0.401, runtime 10.0.12, Release, x64 RyuJIT |
| Database | `postgres:17-alpine` in Docker (Testcontainers), default settings, `max_connections=200` |
| KMS | `FieldCrypto.DevKms` (OCI Vault API subset, OCI request signatures) in-process on Kestrel, loopback HTTP, no simulated latency |
| Host load | **shared and loaded**: another agent's build and benchmark ran at the same time. Windows CPU load was 74 % when the end-to-end run started and 46 % when it ended; 24 % at the start of the micro-benchmarks. Six other containers were running. |

Throughput figures are the **median of three runs**, with each run listed. Latencies are percentiles of sequential calls
after a warm-up. The spread between runs (for example 1,770 / 3,014 / 6,387 encrypted inserts per second) is the host
load, not the code; treat ratios measured within one run as more reliable than absolute numbers.

## How to reproduce

```bash
dotnet run -c Release --project benchmarks/FieldCrypto.Benchmarks -- micro --filter '*'     # BenchmarkDotNet
dotnet run -c Release --project benchmarks/FieldCrypto.Benchmarks -- macro 10000 3          # end-to-end, needs Docker
```

The end-to-end harness starts PostgreSQL with Testcontainers and the development KMS in-process, and writes
`benchmark-results/macro-<timestamp>.json`.

## 1. Per-field CPU cost (BenchmarkDotNet, warm data key cache)

| Operation | Mean | Allocated |
|---|---:|---:|
| encrypt 11-character national id | 1,391.5 ns | 336 B |
| decrypt 11-character national id | 1,181.8 ns | 272 B |
| encrypt 1 KiB note (row-bound context) | 2,199.9 ns | 2,376 B |
| decrypt 1 KiB note (row-bound context) | 1,850.7 ns | 3,320 B |
| blind index, digits normaliser, 16 bits | 491.1 ns | 192 B |
| blind index, Turkish case fold, 12 bits | 604.1 ns | 168 B |
| local KEK wrap (in-process, for comparison) | 1,295 ns | 456 B |
| local KEK unwrap | 1,185 ns | 392 B |
| OCI request signature (RSA-2048 PKCS#1 v1.5) | 939.8 µs | 3,088 B |

Reading: the cost of a field is about a microsecond and is dominated by fixed per-call work (an `AesGcm` instance per
operation, the associated data), not by length: a 1 KiB note costs less than twice an 11-digit id. Signing one OCI
request costs almost a millisecond of CPU, another reason to call the KMS once per data key and not per value.

## 2. KMS call latency (300 sequential unwraps after 50 warm-up)

| Path | p50 | p95 |
|---|---:|---:|
| local KEK, in-process | 5.6 µs | 9.3 µs |
| DevKms over the OCI API, async (`HttpClient.SendAsync`) | 1.67 ms | 3.07 ms |
| DevKms over the OCI API, sync (`HttpClient.Send`, EF Core converter path) | 1.63 ms | 2.27 ms |

This is loopback HTTP plus request signing and verification; a real OCI Vault adds network distance and server-side
work. Not measured: no OCI tenancy was available.

## 3. Write path: EF Core inserts, 10,000 patients

Five encrypted properties (national id, full name, surname, e-mail, phone) and three blind indexes per patient, batches
of 500, KMS = DevKms over the OCI API.

| Variant | Patients/s (median) | Runs | KMS wraps |
|---|---:|---|---:|
| plaintext table, same entity | 14,466 | 4,078 / 14,893 / 14,466 | 0 |
| encrypted, data key cache (FieldCrypto default) | 3,014 | 1,770 / 3,014 / 6,387 | **2** (1 data key + blind index root) |
| encrypted, no cache: a new data key per value (300 patients) | 72 | 66 / 72 / 80 | **1,429** for 300 patients |

The cache is what makes envelope encryption affordable: without it every value costs a KMS round trip and a key row,
and throughput drops about 40x. Each encrypted run also builds a new EF Core model (a new key ring means new
converters), which is part of the measured time.

## 4. Reading all 10,000 patients

| Read | Median | Runs |
|---|---:|---|
| first read by a new key ring (EF model build + 1 KMS unwrap + decrypt 5 fields x 10,000) | 396 ms | 781 / 305 / 396 |
| warm read, encrypted | 315 ms | 315 / 295 / 524 |
| warm read, plaintext | 60 ms | 60 / 165 / 29 |

One unwrap serves the whole table. A full-table read of encrypted rows costs about 5x the plaintext read here: 50,000
decryptions at ~1.2 µs each account for ~60 ms, the rest is EF Core running a value converter per value and materialising
`bytea`.

## 5. Equality lookup by national id (300 sequential lookups, 10,000 rows)

| Lookup | p50 | p95 |
|---|---:|---:|
| blind index (16 bits) in SQL, decrypt candidates, drop false positives | 1.13 ms | 8.44 ms |
| plaintext b-tree on the plaintext table | 0.67 ms | 1.51 ms |

1.15 candidate rows per lookup on average, exactly the expected `1 + 10,000 / 2^16`.

## 6. Blind index false positives: 100,000 synthetic national ids, 200 lookups per length

| Bits | False positives per lookup | Expected `(n-1)/2^b` | Distinct index values | Largest bucket | Rows alone in their bucket |
|---:|---:|---:|---:|---:|---:|
| 8 | 391.315 | 390.621 | 256 | 443 | 0 |
| 12 | 24.565 | 24.414 | 4,096 | 44 | 0 |
| 16 | 1.475 | 1.526 | 51,342 | 9 | 21,835 |
| 20 | 0.130 | 0.095 | 95,381 | 4 | 90,900 |
| 24 | 0.010 | 0.006 | 99,668 | 3 | 99,337 |
| 32 | 0.000 | 0.000 | 99,999 | 2 | 99,998 |

The planner's formula holds within sampling noise. The last column is the leakage side: at 16 bits, 22 % of these
unique-valued rows still sit alone in their bucket (an equal index value then points at one row). At 12 bits none do, at
the price of ~25 extra decryptions per lookup. `BlindIndexPlanner.Recommend(100_000, 50)` returns 11..15 bits.

## 7. Rotation

| Operation | Median | Runs |
|---|---:|---|
| KEK rotation, 1,000 data keys, over the OCI API | 4,508 ms (4.5 ms per key) | 4,018 / 4,508 / 5,427 |
| per key: unwrap / wrap / compare-and-set UPDATE (p50) | 1.39 / 1.35 / 0.89 ms | 100 keys |
| KEK rotation of the 10,000-patient dataset (2 keys) | 13.8 ms | 24 / 14 / 14 |
| data key retirement: re-encrypt 10,000 rows x 5 columns, batches of 1,000 | 8,626 rows/s | 7,636 / 8,626 / 10,028 |

A KEK rotation costs per data key and touches no data row (the demo checks an MD5 fingerprint of every data row
before and after). Re-encryption is the O(rows) operation; at the measured rate, 1,000,000 rows would take about two
minutes of job time, but that is an extrapolation, not a measurement.

An earlier smoke run of the 1,000-key rewrap took 36 ms per key while the other agent's load peaked; the per-phase
breakdown above was added to see where time goes and the three recorded runs are the ones reported.

## 8. Storage

| | Encrypted | Plaintext |
|---|---:|---:|
| `national_id` value (`pg_column_size`, 11 digits) | 57 bytes | 12 bytes |
| `patients` table incl. indexes, 10,000 rows | 5.00 MiB (+3 blind index b-trees) | 2.20 MiB |

45 bytes of format overhead plus the `bytea` header per encrypted value.
