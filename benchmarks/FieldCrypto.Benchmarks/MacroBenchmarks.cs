using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using FieldCrypto.BlindIndexing;
using FieldCrypto.Dapper;
using FieldCrypto.Demo.Clinic;
using FieldCrypto.DevKms;
using FieldCrypto.EntityFrameworkCore;
using FieldCrypto.Keys;
using FieldCrypto.Kms;
using FieldCrypto.Oci;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;

namespace FieldCrypto.Benchmarks;

/// <summary>
/// End-to-end measurements against PostgreSQL 17 (Testcontainers) and the development KMS over loopback HTTP.
/// Throughput numbers are the median of three runs; latencies are percentiles of sequential calls after a warm-up.
/// </summary>
public sealed class MacroBenchmarks(int patients, int runs, TextWriter output)
{
    private const string KeyOcid = "ocid1.key.oc1.dev.fieldcrypto.bench";
    private static readonly DateTimeOffset Created = DateTimeOffset.Parse("2026-11-13T09:00:00Z", CultureInfo.InvariantCulture);
    private readonly Dictionary<string, object> _results = [];

    public async Task<Dictionary<string, object>> RunAsync()
    {
        await using var postgres = new PostgreSqlBuilder("postgres:17-alpine").WithCommand("-c", "max_connections=200").Build();
        await postgres.StartAsync();
        await using var kmsHost = await StartKmsAsync();
        var kms = kmsHost.Service;

        _results["environment"] = new
        {
            os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            dotnet = Environment.Version.ToString(),
            cpus = Environment.ProcessorCount,
            postgres = "postgres:17-alpine (Testcontainers, Docker Desktop)",
            patients,
            runs,
        };

        await KmsLatency(kms);
        var data = await WritePath(postgres, kms);
        await ColdRead(data);
        await Lookups(data);
        await Storage(data);
        await Rotation(postgres, kms, data);
        await FalsePositiveSweep(postgres);
        return _results;
    }

    private async Task KmsLatency(OciVaultKeyEncryptionService oci)
    {
        Section("KMS call latency (sequential, 300 calls after 50 warm-up)");
        var local = LocalKeyEncryptionService.CreateEphemeral();
        var context = new KeyWrapContext(Guid.CreateVersion7(), "data");
        var key = RandomNumberGenerator.GetBytes(32);
        var localWrapped = local.Wrap(key, context).Ciphertext;
        var ociWrapped = (await oci.WrapAsync(key, context)).Ciphertext;

        var localUnwrap = Measure(300, 50, () => local.Unwrap(localWrapped, context));
        var ociAsync = await MeasureAsync(300, 50, () => oci.UnwrapAsync(ociWrapped, context));
        var ociSync = Measure(300, 50, () => oci.Unwrap(ociWrapped, context));
        _results["kmsLatency"] = new { localUnwrap, ociDevKmsAsync = ociAsync, ociDevKmsSync = ociSync };
        Line($"local in-process unwrap        p50 {localUnwrap.P50Ms * 1000:0.0} us   p95 {localUnwrap.P95Ms * 1000:0.0} us");
        Line($"DevKms (OCI API) async unwrap  p50 {ociAsync.P50Ms:0.00} ms   p95 {ociAsync.P95Ms:0.00} ms");
        Line($"DevKms (OCI API) sync unwrap   p50 {ociSync.P50Ms:0.00} ms   p95 {ociSync.P95Ms:0.00} ms");
    }

    private async Task<Dataset> WritePath(PostgreSqlContainer postgres, OciVaultKeyEncryptionService kms)
    {
        Section($"Write path: EF Core inserts of {patients:N0} patients (5 encrypted fields, 3 blind indexes) vs plaintext");
        var rows = SyntheticPatients.Generate(patients, seed: 99, Created);
        var cached = new List<double>();
        var plain = new List<double>();
        Dataset? keep = null;
        long wraps = 0;
        for (var run = 0; run < runs; run++)
        {
            var dataSource = await CreateDatabaseAsync(postgres, $"write_{run}");
            var ring = new KeyRing(kms, new PostgresDataKeyStore(dataSource));
            await ring.InitializeAsync();
            var encryptor = new FieldEncryptor(ring);
            var indexer = new BlindIndexer(ring);
            var stopwatch = Stopwatch.StartNew();
            foreach (var chunk in Clone(rows).Chunk(500))
            {
                await using var db = new ClinicDbContext(ClinicDbContext.Options(dataSource, indexer), encryptor);
                db.Patients.AddRange(chunk);
                await db.SaveChangesAsync();
            }

            cached.Add(patients / stopwatch.Elapsed.TotalSeconds);
            wraps = ring.Statistics.KmsWraps;

            stopwatch.Restart();
            foreach (var chunk in Clone(rows).Chunk(500))
            {
                await using var db = new PlainClinicContext(dataSource);
                db.Patients.AddRange(chunk);
                await db.SaveChangesAsync();
            }

            plain.Add(patients / stopwatch.Elapsed.TotalSeconds);
            if (keep is null)
            {
                keep = new Dataset(dataSource, ring, encryptor, indexer, rows, kms);
            }
            else
            {
                ring.Dispose();
                await dataSource.DisposeAsync();
            }
        }

        // Without the data key cache: every field value gets its own data key (one KMS wrap and one key row each).
        const int uncachedPatients = 300;
        var uncached = new List<double>();
        long uncachedWraps = 0;
        for (var run = 0; run < runs; run++)
        {
            await using var dataSource = await CreateDatabaseAsync(postgres, $"nocache_{run}");
            using var ring = new KeyRing(kms, new PostgresDataKeyStore(dataSource), new KeyRingOptions { MaxMessagesPerDataKey = 1 });
            await ring.InitializeAsync();
            var encryptor = new FieldEncryptor(ring);
            var indexer = new BlindIndexer(ring);
            var stopwatch = Stopwatch.StartNew();
            await using (var db = new ClinicDbContext(ClinicDbContext.Options(dataSource, indexer), encryptor))
            {
                db.Patients.AddRange(Clone(rows.Take(uncachedPatients)));
                await db.SaveChangesAsync();
            }

            uncached.Add(uncachedPatients / stopwatch.Elapsed.TotalSeconds);
            uncachedWraps = ring.Statistics.KmsWraps;
        }

        _results["writePath"] = new
        {
            encryptedPatientsPerSecond = Median(cached),
            plaintextPatientsPerSecond = Median(plain),
            encryptedRuns = cached,
            plaintextRuns = plain,
            kmsWrapsWithCache = wraps,
            noCachePatients = uncachedPatients,
            noCachePatientsPerSecond = Median(uncached),
            noCacheRuns = uncached,
            kmsWrapsWithoutCache = uncachedWraps,
        };
        Line($"encrypted (data key cache): {Median(cached):N0} patients/s  [{Join(cached)}], {wraps} KMS wraps (incl. blind index root)");
        Line($"plaintext baseline:         {Median(plain):N0} patients/s  [{Join(plain)}]");
        Line($"no cache, key per value:    {Median(uncached):N0} patients/s  [{Join(uncached)}], {uncachedWraps} KMS wraps for {uncachedPatients} patients");
        return keep!;
    }

    private async Task ColdRead(Dataset data)
    {
        Section($"Read all {patients:N0} patients (EF Core, 5 encrypted fields): first read by a new key ring, then warm");
        var cold = new List<double>();
        var warm = new List<double>();
        var plain = new List<double>();
        long unwraps = 0;
        for (var run = 0; run < runs; run++)
        {
            // A new key ring means a new encryptor, so EF Core also builds a new model (the converters capture it):
            // the first read pays model building, the data key unwrap and decryption, as a freshly started process would.
            using var ring = new KeyRing(data.Kms, new PostgresDataKeyStore(data.DataSource));
            var encryptor = new FieldEncryptor(ring);
            var indexer = new BlindIndexer(ring);
            var stopwatch = Stopwatch.StartNew();
            await using (var db = new ClinicDbContext(ClinicDbContext.Options(data.DataSource, indexer), encryptor))
            {
                _ = await db.Patients.AsNoTracking().ToListAsync();
            }

            cold.Add(stopwatch.Elapsed.TotalMilliseconds);
            unwraps = ring.Statistics.KmsUnwraps;
            stopwatch.Restart();
            await using (var db = new ClinicDbContext(ClinicDbContext.Options(data.DataSource, indexer), encryptor))
            {
                _ = await db.Patients.AsNoTracking().ToListAsync();
            }

            warm.Add(stopwatch.Elapsed.TotalMilliseconds);
            await using (var db = new PlainClinicContext(data.DataSource))
            {
                _ = await db.Patients.AsNoTracking().ToListAsync();
            }

            stopwatch.Restart();
            await using (var db = new PlainClinicContext(data.DataSource))
            {
                _ = await db.Patients.AsNoTracking().ToListAsync();
            }

            plain.Add(stopwatch.Elapsed.TotalMilliseconds);
        }

        _results["read"] = new { firstReadMs = Median(cold), warmReadMs = Median(warm), plaintextWarmReadMs = Median(plain), firstRuns = cold, warmRuns = warm, plaintextRuns = plain, kmsUnwrapsOnFirstRead = unwraps };
        Line($"first read (model build + {unwraps} unwrap + decrypt): {Median(cold):N0} ms [{Join(cold)}]");
        Line($"warm read, encrypted: {Median(warm):N0} ms [{Join(warm)}]; warm read, plaintext: {Median(plain):N0} ms [{Join(plain)}]");
    }

    private async Task Lookups(Dataset data)
    {
        Section("Equality lookup by national id (300 sequential lookups after 30 warm-up)");
        var random = new Random(5);
        var targets = Enumerable.Range(0, 330).Select(_ => data.Rows[random.Next(data.Rows.Count)].NationalId).ToList();
        var candidates = new List<int>();
        var i = 0;
        await using var encryptedDb = new ClinicDbContext(ClinicDbContext.Options(data.DataSource, data.Indexer), data.Encryptor);
        var blind = await MeasureAsync(300, 30, async () =>
        {
            var result = await encryptedDb.Patients.WhereBlindIndexMatchesAsync(data.Indexer, p => p.NationalId, targets[i++ % targets.Count], q => q.AsNoTracking());
            candidates.Add(result.Candidates);
            if (result.Matches.Count != 1)
            {
                throw new InvalidOperationException("lookup missed");
            }
        });
        var j = 0;
        await using var plainDb = new PlainClinicContext(data.DataSource);
        var plain = await MeasureAsync(300, 30, async () =>
        {
            var id = targets[j++ % targets.Count];
            _ = await plainDb.Patients.AsNoTracking().SingleAsync(p => p.NationalId == id);
        });
        var meanCandidates = candidates.Average();
        _results["lookup"] = new
        {
            blindIndex = blind,
            plaintextIndex = plain,
            meanCandidates,
            expectedFalsePositives = BlindIndexPlanner.ExpectedFalsePositives(patients, ClinicIndexes.NationalId.Bits),
        };
        Line($"blind index (16 bits) + decrypt: p50 {blind.P50Ms:0.00} ms  p95 {blind.P95Ms:0.00} ms, {meanCandidates:0.00} candidate rows per lookup (expected {1 + BlindIndexPlanner.ExpectedFalsePositives(patients, 16):0.00})");
        Line($"plaintext b-tree:                p50 {plain.P50Ms:0.00} ms  p95 {plain.P95Ms:0.00} ms");
    }

    private async Task Storage(Dataset data)
    {
        Section("Storage");
        await using var connection = await data.DataSource.OpenConnectionAsync();
        var sizes = await connection.QuerySingleAsync<(double Encrypted, double Plain, long EncryptedTable, long PlainTable)>(
            """
            SELECT (SELECT avg(pg_column_size(national_id)) FROM patients)::float8,
                   (SELECT avg(pg_column_size(national_id)) FROM patients_plain)::float8,
                   pg_total_relation_size('patients'), pg_total_relation_size('patients_plain')
            """);
        _results["storage"] = new { nationalIdEncryptedBytes = sizes.Encrypted, nationalIdPlainBytes = sizes.Plain, encryptedTableBytes = sizes.EncryptedTable, plainTableBytes = sizes.PlainTable };
        Line($"national_id column: {sizes.Encrypted:0.0} bytes encrypted vs {sizes.Plain:0.0} plaintext (pg_column_size)");
        Line($"table incl. indexes: {sizes.EncryptedTable / 1048576.0:0.00} MiB encrypted (+3 blind index b-trees) vs {sizes.PlainTable / 1048576.0:0.00} MiB plaintext");
    }

    private async Task Rotation(PostgreSqlContainer postgres, OciVaultKeyEncryptionService kms, Dataset data)
    {
        Section("Rotation");

        // KEK rotation cost is per data key, so measure it on a store with many keys: 1,000 values, one data key each.
        var rewrapTimes = new List<double>();
        int keys = 0;
        await using (var dataSource = await CreateDatabaseAsync(postgres, "rewrap"))
        {
            using var ring = new KeyRing(kms, new PostgresDataKeyStore(dataSource), new KeyRingOptions { MaxMessagesPerDataKey = 1 });
            var encryptor = new FieldEncryptor(ring);
            for (var n = 0; n < 1000; n++)
            {
                await encryptor.EncryptAsync("x", new EncryptionContext("t", "c"));
            }

            // Where a rewrap's time goes: one unwrap, one wrap and one compare-and-set UPDATE per key.
            var store = new PostgresDataKeyStore(dataSource);
            var sampleRecords = (await store.ListAsync()).Where(r => r.Purpose == DataKeyPurpose.Data).Take(100).ToList();
            var unwrapMs = new List<double>();
            var wrapMs = new List<double>();
            var updateMs = new List<double>();
            foreach (var record in sampleRecords)
            {
                var context = new KeyWrapContext(record.Id, "data");
                var start = Stopwatch.GetTimestamp();
                var plaintext = await kms.UnwrapAsync(record.WrappedKey, context);
                unwrapMs.Add(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
                start = Stopwatch.GetTimestamp();
                var wrapped = await kms.WrapAsync(plaintext, context);
                wrapMs.Add(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
                start = Stopwatch.GetTimestamp();
                await store.TryUpdateWrappingAsync(record.Id, record.KekId, record.KekVersion, record.KekId, wrapped.KeyVersion, wrapped.Ciphertext);
                updateMs.Add(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
            }

            Line($"per key: unwrap p50 {Latency.From([.. unwrapMs]).P50Ms:0.00} ms, wrap p50 {Latency.From([.. wrapMs]).P50Ms:0.00} ms, UPDATE p50 {Latency.From([.. updateMs]).P50Ms:0.00} ms");
            _results["rewrapBreakdown"] = new { unwrap = Latency.From([.. unwrapMs]), wrap = Latency.From([.. wrapMs]), update = Latency.From([.. updateMs]) };

            for (var run = 0; run < runs; run++)
            {
                await kms.CreateKeyVersionAsync();
                var stopwatch = Stopwatch.StartNew();
                var result = await ring.RewrapAsync();
                rewrapTimes.Add(stopwatch.Elapsed.TotalMilliseconds);
                keys = result.Rewrapped;
            }
        }

        var dataKeysInDataset = (await data.Ring.Store.ListAsync()).Count;
        var datasetRewrap = new List<double>();
        for (var run = 0; run < runs; run++)
        {
            await kms.CreateKeyVersionAsync();
            var stopwatch = Stopwatch.StartNew();
            await data.Ring.RewrapAsync();
            datasetRewrap.Add(stopwatch.Elapsed.TotalMilliseconds);
        }

        // Data key retirement: every row of the dataset moves to a new data key, five columns per row.
        var target = new ReencryptionTarget("patients", "id", "uuid", [new("national_id", false), new("full_name", false), new("surname", false), new("email", false), new("phone", false)]);
        var reencrypt = new List<double>();
        for (var run = 0; run < runs; run++)
        {
            await data.Ring.RetireActiveDataKeyAsync();
            foreach (var record in (await data.Ring.Store.ListAsync()).Where(r => r.Purpose == DataKeyPurpose.Data && r.RetiredAt is null))
            {
                await data.Ring.RetireDataKeyAsync(record.Id);
            }

            var result = await new ColumnReencryptor(data.DataSource, data.Encryptor).ReencryptRetiredAsync(target, batchSize: 1000);
            if (result.RowsReencrypted != patients)
            {
                throw new InvalidOperationException($"re-encrypted {result.RowsReencrypted} of {patients}");
            }

            reencrypt.Add(result.RowsPerSecond);
        }

        _results["rotation"] = new
        {
            rewrapKeys = keys,
            rewrapMs = Median(rewrapTimes),
            rewrapRuns = rewrapTimes,
            datasetDataKeys = dataKeysInDataset,
            datasetRewrapMs = Median(datasetRewrap),
            datasetRewrapRuns = datasetRewrap,
            reencryptRowsPerSecond = Median(reencrypt),
            reencryptRuns = reencrypt,
        };
        Line($"KEK rotation, {keys:N0} data keys over the OCI API: {Median(rewrapTimes):N0} ms [{Join(rewrapTimes)}] ({Median(rewrapTimes) / keys:0.00} ms per key)");
        Line($"KEK rotation of the {patients:N0}-patient dataset ({dataKeysInDataset} keys): {Median(datasetRewrap):0.0} ms [{Join(datasetRewrap)}]; data rows touched: 0");
        Line($"data key retirement, re-encrypt {patients:N0} rows x 5 columns: {Median(reencrypt):N0} rows/s [{Join(reencrypt)}]");
    }

    private async Task FalsePositiveSweep(PostgreSqlContainer postgres)
    {
        const int rows = 100_000;
        int[] bits = [8, 12, 16, 20, 24, 32];
        Section($"Blind index false positives: {rows:N0} national ids, 200 lookups per length");
        await using var dataSource = await CreateDatabaseAsync(postgres, "fpsweep");
        using var ring = new KeyRing(LocalKeyEncryptionService.CreateEphemeral(), new InMemoryDataKeyStore());
        var indexer = new BlindIndexer(ring);
        var definitions = bits.Select(b => new BlindIndexDefinition("people", "national_id", b, TextNormalizers.DigitsOnly)).ToArray();
        var random = new Bogus.Randomizer(17);
        var ids = new HashSet<string>(StringComparer.Ordinal);
        while (ids.Count < rows)
        {
            ids.Add(SyntheticPatients.NationalId(random));
        }

        var list = ids.ToList();
        await using (var connection = await dataSource.OpenConnectionAsync())
        {
            await connection.ExecuteAsync($"CREATE TABLE sweep (id int PRIMARY KEY, {string.Join(", ", bits.Select(b => $"b{b} bigint"))})");
            await using (var writer = await connection.BeginBinaryImportAsync($"COPY sweep (id, {string.Join(", ", bits.Select(b => $"b{b}"))}) FROM STDIN (FORMAT BINARY)"))
            {
                for (var n = 0; n < list.Count; n++)
                {
                    await writer.StartRowAsync();
                    await writer.WriteAsync(n);
                    foreach (var definition in definitions)
                    {
                        await writer.WriteAsync(indexer.Compute(list[n], definition));
                    }
                }

                await writer.CompleteAsync();
            }

            foreach (var b in bits)
            {
                await connection.ExecuteAsync($"CREATE INDEX ON sweep (b{b})");
            }
        }

        var sample = Enumerable.Range(0, 200).Select(_ => list[random.Number(0, list.Count - 1)]).ToList();
        var sweep = new List<object>();
        await using (var connection = await dataSource.OpenConnectionAsync())
        {
            for (var k = 0; k < bits.Length; k++)
            {
                var b = bits[k];
                var counts = new List<int>();
                foreach (var id in sample)
                {
                    counts.Add(await connection.ExecuteScalarAsync<int>($"SELECT count(*) FROM sweep WHERE b{b} = @v", new { v = indexer.Compute(id, definitions[k]) }));
                }

                var distinct = await connection.ExecuteScalarAsync<long>($"SELECT count(DISTINCT b{b}) FROM sweep");
                var largest = await connection.ExecuteScalarAsync<long>($"SELECT max(c) FROM (SELECT count(*) c FROM sweep GROUP BY b{b}) s");
                var measured = counts.Average() - 1;
                var expected = (rows - 1) / Math.Pow(2, b);
                var unique = await connection.ExecuteScalarAsync<long>($"SELECT count(*) FROM (SELECT b{b} FROM sweep GROUP BY b{b} HAVING count(*) = 1) s");
                sweep.Add(new { bits = b, meanFalsePositives = measured, expectedFalsePositives = expected, distinctValues = distinct, largestBucket = largest, rowsAloneInBucket = unique });
                Line($"{b,2} bits: {measured,10:0.000} false positives/lookup (expected {expected,10:0.000}); {distinct,7:N0} distinct values, largest bucket {largest,5:N0}, rows alone in their bucket {unique,7:N0}");
            }
        }

        _results["falsePositiveSweep"] = sweep;
    }

    private static async Task<NpgsqlDataSource> CreateDatabaseAsync(PostgreSqlContainer postgres, string name)
    {
        await using (var admin = NpgsqlDataSource.Create(postgres.GetConnectionString()))
        await using (var command = admin.CreateCommand($"CREATE DATABASE {name}"))
        {
            await command.ExecuteNonQueryAsync();
        }

        var dataSource = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Database = name }.ConnectionString);
        await ClinicSchema.CreateAsync(dataSource);
        await using var command2 = dataSource.CreateCommand(PlainClinicContext.Sql);
        await command2.ExecuteNonQueryAsync();
        return dataSource;
    }

    private static async Task<KmsHost> StartKmsAsync()
    {
        var clientKey = RSA.Create(2048);
        var keyId = $"{DevKmsApp.TenancyOcid}/{DevKmsApp.UserOcid}/{OciApiKey.Fingerprint(clientKey)}";
        var app = DevKmsApp.Build(["--urls", "http://127.0.0.1:0", "--Logging:LogLevel:Default=Warning"], o =>
        {
            o.KeyIds.Clear();
            o.KeyIds.Add(KeyOcid);
            o.TrustedKeys[keyId] = clientKey.ExportSubjectPublicKeyInfoPem();
        });
        await app.StartAsync();
        var endpoint = new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First());
        var service = OciVaultKeyEncryptionService.Create(
            new OciVaultOptions { CryptoEndpoint = endpoint, ManagementEndpoint = endpoint, KeyId = KeyOcid },
            new OciApiKey(DevKmsApp.TenancyOcid, DevKmsApp.UserOcid, OciApiKey.Fingerprint(clientKey), clientKey));
        return new KmsHost(app, service);
    }

    private static IEnumerable<Patient> Clone(IEnumerable<Patient> rows) => rows.Select(p => new Patient
    {
        Id = p.Id,
        NationalId = p.NationalId,
        FullName = p.FullName,
        Surname = p.Surname,
        Email = p.Email,
        Phone = p.Phone,
        BirthYear = p.BirthYear,
        CreatedAt = p.CreatedAt,
    });

    private static Latency Measure(int count, int warmup, Action action)
    {
        for (var n = 0; n < warmup; n++)
        {
            action();
        }

        var samples = new double[count];
        for (var n = 0; n < count; n++)
        {
            var start = Stopwatch.GetTimestamp();
            action();
            samples[n] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        }

        return Latency.From(samples);
    }

    private static async Task<Latency> MeasureAsync(int count, int warmup, Func<Task> action)
    {
        for (var n = 0; n < warmup; n++)
        {
            await action();
        }

        var samples = new double[count];
        for (var n = 0; n < count; n++)
        {
            var start = Stopwatch.GetTimestamp();
            await action();
            samples[n] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        }

        return Latency.From(samples);
    }

    private static double Median(List<double> values)
    {
        var sorted = values.Order().ToList();
        return sorted.Count % 2 == 1 ? sorted[sorted.Count / 2] : (sorted[(sorted.Count / 2) - 1] + sorted[sorted.Count / 2]) / 2;
    }

    private static string Join(List<double> values) => string.Join(", ", values.Select(v => v.ToString("N0", CultureInfo.InvariantCulture)));

    private void Section(string title)
    {
        output.WriteLine();
        output.WriteLine("=== " + title);
    }

    private void Line(string text) => output.WriteLine("  " + text);

    public static string ToJson(Dictionary<string, object> results) => JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true });

    private sealed record Dataset(NpgsqlDataSource DataSource, KeyRing Ring, FieldEncryptor Encryptor, BlindIndexer Indexer, List<Patient> Rows, IKeyEncryptionService Kms);

    private sealed class KmsHost(WebApplication app, OciVaultKeyEncryptionService service) : IAsyncDisposable
    {
        public OciVaultKeyEncryptionService Service { get; } = service;

        public async ValueTask DisposeAsync()
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }
}

public sealed record Latency(double P50Ms, double P95Ms, double P99Ms, double MeanMs)
{
    public static Latency From(double[] samples)
    {
        var sorted = samples.Order().ToArray();
        double At(double q) => sorted[Math.Min(sorted.Length - 1, (int)Math.Ceiling(q * sorted.Length) - 1)];
        return new Latency(At(0.50), At(0.95), At(0.99), samples.Average());
    }
}

/// <summary>The same patients without encryption: the baseline every encrypted number is compared with.</summary>
internal sealed class PlainClinicContext(NpgsqlDataSource dataSource) : DbContext(new DbContextOptionsBuilder<PlainClinicContext>().UseNpgsql(dataSource).Options)
{
    public const string Sql = """
        CREATE TABLE IF NOT EXISTS patients_plain (
            id uuid PRIMARY KEY, national_id text NOT NULL, full_name text NOT NULL, surname text NOT NULL,
            email text NULL, phone text NULL, birth_year integer NOT NULL, created_at timestamptz NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_patients_plain_national_id ON patients_plain (national_id);
        """;

    public DbSet<Patient> Patients => Set<Patient>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.Entity<Patient>(p =>
    {
        p.ToTable("patients_plain");
        p.Property(x => x.Id).HasColumnName("id");
        p.Property(x => x.NationalId).HasColumnName("national_id");
        p.Property(x => x.FullName).HasColumnName("full_name");
        p.Property(x => x.Surname).HasColumnName("surname");
        p.Property(x => x.Email).HasColumnName("email");
        p.Property(x => x.Phone).HasColumnName("phone");
        p.Property(x => x.BirthYear).HasColumnName("birth_year");
        p.Property(x => x.CreatedAt).HasColumnName("created_at");
        p.Ignore(x => x.NationalIdIndex);
        p.Ignore(x => x.SurnameIndex);
        p.Ignore(x => x.EmailIndex);
    });
}
