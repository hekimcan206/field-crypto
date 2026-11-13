using FieldCrypto.BlindIndexing;
using FieldCrypto.Dapper;
using FieldCrypto.Demo.Clinic;
using FieldCrypto.Keys;
using FieldCrypto.Kms;
using Npgsql;
using Testcontainers.PostgreSql;

[assembly: AssemblyFixture(typeof(FieldCrypto.IntegrationTests.Infrastructure.PostgresEnvironment))]

namespace FieldCrypto.IntegrationTests.Infrastructure;

/// <summary>One PostgreSQL 17 container per run; every test gets its own database with the clinic schema.</summary>
public sealed class PostgresEnvironment : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase("postgres")
        .Build();

    private int _databases;

    public async ValueTask InitializeAsync() => await _postgres.StartAsync();

    public async ValueTask DisposeAsync() => await _postgres.DisposeAsync();

    public async Task<TestDatabase> CreateDatabaseAsync(IKeyEncryptionService? kms = null, KeyRingOptions? options = null)
    {
        var name = $"fc_{Interlocked.Increment(ref _databases)}";
        await using (var admin = NpgsqlDataSource.Create(_postgres.GetConnectionString()))
        await using (var command = admin.CreateCommand($"CREATE DATABASE {name}"))
        {
            await command.ExecuteNonQueryAsync();
        }

        var builder = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString()) { Database = name, Timeout = 30 };
        var dataSource = NpgsqlDataSource.Create(builder.ConnectionString);
        await ClinicSchema.CreateAsync(dataSource);
        return new TestDatabase(dataSource, kms ?? LocalKeyEncryptionService.CreateEphemeral(), options);
    }
}

public sealed class TestDatabase : IAsyncDisposable
{
    public TestDatabase(NpgsqlDataSource dataSource, IKeyEncryptionService kms, KeyRingOptions? options)
    {
        DataSource = dataSource;
        Kms = kms;
        Store = new PostgresDataKeyStore(dataSource);
        Ring = new KeyRing(kms, Store, options);
        Encryptor = new FieldEncryptor(Ring);
        Indexer = new BlindIndexer(Ring);
    }

    public NpgsqlDataSource DataSource { get; }

    public IKeyEncryptionService Kms { get; }

    public PostgresDataKeyStore Store { get; }

    public KeyRing Ring { get; }

    public FieldEncryptor Encryptor { get; }

    public BlindIndexer Indexer { get; }

    public ClinicDbContext Clinic() => new(ClinicDbContext.Options(DataSource, Indexer), Encryptor);

    /// <summary>Another process: same database and KMS, cold caches.</summary>
    public (KeyRing Ring, FieldEncryptor Encryptor, BlindIndexer Indexer) OtherProcess()
    {
        var ring = new KeyRing(Kms, new PostgresDataKeyStore(DataSource));
        return (ring, new FieldEncryptor(ring), new BlindIndexer(ring));
    }

    public async ValueTask DisposeAsync()
    {
        Ring.Dispose();
        await DataSource.DisposeAsync();
    }
}
