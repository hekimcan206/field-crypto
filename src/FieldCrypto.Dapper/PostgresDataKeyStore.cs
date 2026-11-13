using System.Data.Common;
using Dapper;
using FieldCrypto.Keys;

namespace FieldCrypto.Dapper;

/// <summary>
/// Data key store in a PostgreSQL table. Holds only wrapped keys: a database dump or a read-only attacker gets
/// nothing usable without the KMS. Create the table with <see cref="CreateTableSql"/> (or your migration tool).
/// </summary>
/// <remarks>
/// The application role needs SELECT, INSERT and UPDATE on this table, never DELETE: deleting a data key is
/// crypto-shredding every value it encrypted, an operation for a separate, audited role.
/// </remarks>
public sealed class PostgresDataKeyStore : IDataKeyStore
{
    private readonly DbDataSource _dataSource;
    private readonly string _table;

    public PostgresDataKeyStore(DbDataSource dataSource, string table = "field_crypto_data_keys")
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
        _table = SqlIdentifier.Quote(table);
    }

    public static string CreateTableSql(string table = "field_crypto_data_keys") => $"""
        CREATE TABLE IF NOT EXISTS {SqlIdentifier.Quote(table)} (
            id           uuid        PRIMARY KEY,
            purpose      smallint    NOT NULL CHECK (purpose IN (1, 2)),
            kek_id       text        NOT NULL,
            kek_version  text        NOT NULL,
            wrapped_key  bytea       NOT NULL,
            created_at   timestamptz NOT NULL,
            retired_at   timestamptz NULL
        );
        """;

    public async Task<bool> TryInsertAsync(DataKeyRecord record, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        return await connection.ExecuteAsync(new CommandDefinition(InsertSql, Parameters(record), cancellationToken: cancellationToken)) == 1;
    }

    public bool TryInsert(DataKeyRecord record)
    {
        using var connection = _dataSource.OpenConnection();
        return connection.Execute(InsertSql, Parameters(record)) == 1;
    }

    public async Task<DataKeyRecord?> FindAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var row = await connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(SelectSql + " WHERE id = @id", new { id }, cancellationToken: cancellationToken));
        return row?.ToRecord();
    }

    public DataKeyRecord? Find(Guid id)
    {
        using var connection = _dataSource.OpenConnection();
        return connection.QuerySingleOrDefault<Row>(SelectSql + " WHERE id = @id", new { id })?.ToRecord();
    }

    public async Task<IReadOnlyList<DataKeyRecord>> ListAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var rows = await connection.QueryAsync<Row>(new CommandDefinition(SelectSql + " ORDER BY created_at, id", cancellationToken: cancellationToken));
        return [.. rows.Select(r => r.ToRecord())];
    }

    public async Task<bool> TryUpdateWrappingAsync(
        Guid id,
        string expectedKekId,
        string expectedKekVersion,
        string newKekId,
        string newKekVersion,
        byte[] newWrappedKey,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        var sql = $"""
            UPDATE {_table} SET kek_id = @newKekId, kek_version = @newKekVersion, wrapped_key = @newWrappedKey
            WHERE id = @id AND kek_id = @expectedKekId AND kek_version = @expectedKekVersion
            """;
        var updated = await connection.ExecuteAsync(new CommandDefinition(
            sql, new { id, expectedKekId, expectedKekVersion, newKekId, newKekVersion, newWrappedKey }, cancellationToken: cancellationToken));
        return updated == 1;
    }

    public async Task RetireAsync(Guid id, DateTimeOffset retiredAt, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        await connection.ExecuteAsync(new CommandDefinition(
            $"UPDATE {_table} SET retired_at = @retiredAt WHERE id = @id AND retired_at IS NULL",
            new { id, retiredAt = retiredAt.UtcDateTime },
            cancellationToken: cancellationToken));
    }

    private string InsertSql => $"""
        INSERT INTO {_table} (id, purpose, kek_id, kek_version, wrapped_key, created_at, retired_at)
        VALUES (@Id, @Purpose, @KekId, @KekVersion, @WrappedKey, @CreatedAt, @RetiredAt)
        ON CONFLICT (id) DO NOTHING
        """;

    private string SelectSql => $"SELECT id AS Id, purpose AS Purpose, kek_id AS KekId, kek_version AS KekVersion, wrapped_key AS WrappedKey, created_at AS CreatedAt, retired_at AS RetiredAt FROM {_table}";

    private static object Parameters(DataKeyRecord r) => new
    {
        r.Id,
        Purpose = (short)r.Purpose,
        r.KekId,
        r.KekVersion,
        r.WrappedKey,
        CreatedAt = r.CreatedAt.UtcDateTime,
        RetiredAt = r.RetiredAt?.UtcDateTime,
    };

    private sealed class Row
    {
        public Guid Id { get; init; }

        public short Purpose { get; init; }

        public string KekId { get; init; } = string.Empty;

        public string KekVersion { get; init; } = string.Empty;

        public byte[] WrappedKey { get; init; } = [];

        public DateTime CreatedAt { get; init; }

        public DateTime? RetiredAt { get; init; }

        public DataKeyRecord ToRecord() => new(
            Id,
            (DataKeyPurpose)Purpose,
            KekId,
            KekVersion,
            WrappedKey,
            new DateTimeOffset(DateTime.SpecifyKind(CreatedAt, DateTimeKind.Utc)),
            RetiredAt is { } retired ? new DateTimeOffset(DateTime.SpecifyKind(retired, DateTimeKind.Utc)) : null);
    }
}
