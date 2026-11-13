using System.Diagnostics;
using FieldCrypto.Keys;
using Npgsql;
using NpgsqlTypes;

namespace FieldCrypto.Dapper;

/// <param name="Name">Column holding FieldCrypto ciphertexts (bytea).</param>
/// <param name="RowBound">True when values were encrypted with the row key in their context (Dapper style).</param>
public sealed record EncryptedColumn(string Name, bool RowBound);

/// <param name="Table">Table to scan.</param>
/// <param name="KeyColumn">Primary key, used for keyset pagination and (for row-bound columns) as the row key.</param>
/// <param name="KeyType">SQL type of the key column, used to cast keyset bounds and batch keys.</param>
public sealed record ReencryptionTarget(string Table, string KeyColumn, string KeyType, IReadOnlyList<EncryptedColumn> Columns);

public readonly record struct ReencryptionResult(int Batches, long RowsExamined, long RowsReencrypted, long Conflicts, TimeSpan Elapsed)
{
    public double RowsPerSecond => Elapsed.TotalSeconds > 0 ? RowsReencrypted / Elapsed.TotalSeconds : 0;
}

/// <summary>
/// Moves rows off retired data keys while the application keeps running: decrypt with the retired key, encrypt with
/// the active one, write back only if the row did not change in between (compare-and-set on the old ciphertexts).
/// This is the O(rows) rotation, needed when a data key itself must go (suspected exposure, age policy); a KEK
/// rotation needs only <see cref="KeyRing.RewrapAsync"/>. PostgreSQL-specific SQL.
/// </summary>
/// <remarks>
/// Rows on retired keys are found in SQL by the data key id in the ciphertext header
/// (<c>substring(col from 2 for 16)</c>), so no row is decrypted unless it needs to be. A row the application
/// updates during the job is counted as a conflict and skipped: its new value is already on the active key.
/// </remarks>
public sealed class ColumnReencryptor(NpgsqlDataSource dataSource, FieldEncryptor encryptor)
{
    private readonly NpgsqlDataSource _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    private readonly FieldEncryptor _encryptor = encryptor ?? throw new ArgumentNullException(nameof(encryptor));

    /// <summary>Re-encrypts every value whose data key is retired in the key store.</summary>
    public async Task<ReencryptionResult> ReencryptRetiredAsync(ReencryptionTarget target, int batchSize = 1000, CancellationToken cancellationToken = default)
    {
        var retired = (await _encryptor.KeyRing.Store.ListAsync(cancellationToken))
            .Where(r => r.Purpose == DataKeyPurpose.Data && r.RetiredAt is not null)
            .Select(r => r.Id)
            .ToList();
        return await ReencryptAsync(target, retired, batchSize, cancellationToken);
    }

    public async Task<ReencryptionResult> ReencryptAsync(ReencryptionTarget target, IReadOnlyCollection<Guid> dataKeyIds, int batchSize = 1000, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(dataKeyIds);
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);
        if (target.Columns.Count == 0)
        {
            throw new ArgumentException("At least one encrypted column is required.", nameof(target));
        }

        var stopwatch = Stopwatch.StartNew();
        if (dataKeyIds.Count == 0)
        {
            return new ReencryptionResult(0, 0, 0, 0, stopwatch.Elapsed);
        }

        if (dataKeyIds.Contains(_encryptor.KeyRing.ActiveDataKeyId ?? Guid.Empty))
        {
            throw new InvalidOperationException("The active data key is in the set to re-encrypt; retire it first so new values use another key.");
        }

        var table = SqlIdentifier.Quote(target.Table);
        var key = SqlIdentifier.Quote(target.KeyColumn);
        var keyType = KeyType(target.KeyType);
        var columns = target.Columns.Select(c => SqlIdentifier.Quote(c.Name)).ToList();
        var ids = new HashSet<Guid>(dataKeyIds);
        var idBytes = dataKeyIds.Select(IdBytes).ToArray();
        var onRetired = string.Join(" OR ", columns.Select(c => $"substring({c} from {CiphertextLayout.SqlDataKeyIdOffset} for {CiphertextLayout.DataKeyIdSize}) = ANY(@ids)"));
        var select = $"""
            SELECT {key}::text AS k, {string.Join(", ", columns)} FROM {table}
            WHERE ({onRetired}) AND (@last IS NULL OR {key} > @last::{keyType})
            ORDER BY {key} LIMIT @batchSize
            """;

        // One UPDATE per batch: unnest the keys, old and new ciphertexts, and only touch rows whose every column still
        // holds the old ciphertext (IS NOT DISTINCT FROM, so NULLs compare too).
        var sets = string.Join(", ", columns.Select((c, i) => $"{c} = v.n{i}"));
        var guards = string.Join(" AND ", columns.Select((c, i) => $"t.{c} IS NOT DISTINCT FROM v.o{i}"));
        var unnestArgs = string.Join(", ", Enumerable.Range(0, columns.Count).SelectMany(i => new[] { $"@o{i}", $"@n{i}" }));
        var unnestNames = string.Join(", ", Enumerable.Range(0, columns.Count).SelectMany(i => new[] { $"o{i}", $"n{i}" }));
        var update = $"""
            UPDATE {table} AS t SET {sets}
            FROM unnest(@keys, {unnestArgs}) AS v(k, {unnestNames})
            WHERE t.{key} = v.k::{keyType} AND {guards}
            """;

        int batches = 0;
        long examined = 0, reencrypted = 0, conflicts = 0;
        string? last = null;
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken);
        while (true)
        {
            var rows = await ReadBatch(connection, select, idBytes, last, batchSize, columns.Count, cancellationToken);
            if (rows.Count == 0)
            {
                break;
            }

            batches++;
            examined += rows.Count;
            last = rows[^1].Key;

            var keys = new string[rows.Count];
            var olds = Enumerable.Range(0, columns.Count).Select(_ => new byte[]?[rows.Count]).ToArray();
            var news = Enumerable.Range(0, columns.Count).Select(_ => new byte[]?[rows.Count]).ToArray();
            for (var r = 0; r < rows.Count; r++)
            {
                keys[r] = rows[r].Key;
                for (var c = 0; c < columns.Count; c++)
                {
                    var column = target.Columns[c];
                    var old = rows[r].Values[c];
                    olds[c][r] = old;
                    news[c][r] = old is not null && CiphertextLayout.TryReadDataKeyId(old, out var id) && ids.Contains(id)
                        ? Reencrypt(old, Context(target, column, keys[r]))
                        : old;
                }
            }

            await using var command = new NpgsqlCommand(update, connection);
            command.Parameters.Add(new NpgsqlParameter("keys", NpgsqlDbType.Array | NpgsqlDbType.Text) { Value = keys });
            for (var c = 0; c < columns.Count; c++)
            {
                command.Parameters.Add(new NpgsqlParameter($"o{c}", NpgsqlDbType.Array | NpgsqlDbType.Bytea) { Value = olds[c] });
                command.Parameters.Add(new NpgsqlParameter($"n{c}", NpgsqlDbType.Array | NpgsqlDbType.Bytea) { Value = news[c] });
            }

            var updated = await command.ExecuteNonQueryAsync(cancellationToken);
            reencrypted += updated;
            conflicts += rows.Count - updated;
        }

        return new ReencryptionResult(batches, examined, reencrypted, conflicts, stopwatch.Elapsed);
    }

    private static async Task<List<(string Key, byte[]?[] Values)>> ReadBatch(
        NpgsqlConnection connection, string sql, byte[][] ids, string? last, int batchSize, int columnCount, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.Add(new NpgsqlParameter("ids", NpgsqlDbType.Array | NpgsqlDbType.Bytea) { Value = ids });
        command.Parameters.Add(new NpgsqlParameter("last", NpgsqlDbType.Text) { Value = (object?)last ?? DBNull.Value });
        command.Parameters.Add(new NpgsqlParameter("batchSize", NpgsqlDbType.Integer) { Value = batchSize });
        var rows = new List<(string, byte[]?[])>(batchSize);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var values = new byte[]?[columnCount];
            for (var c = 0; c < columnCount; c++)
            {
                values[c] = reader.IsDBNull(c + 1) ? null : reader.GetFieldValue<byte[]>(c + 1);
            }

            rows.Add((reader.GetString(0), values));
        }

        return rows;
    }

    private byte[] Reencrypt(byte[] ciphertext, EncryptionContext context)
    {
        var plaintext = _encryptor.DecryptBytes(ciphertext, context);
        try
        {
            return _encryptor.Encrypt(plaintext, context);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static EncryptionContext Context(ReencryptionTarget target, EncryptedColumn column, string rowKey) =>
        column.RowBound ? new EncryptionContext(target.Table, column.Name, rowKey) : new EncryptionContext(target.Table, column.Name);

    private static byte[] IdBytes(Guid id)
    {
        var bytes = new byte[16];
        id.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }

    private static string KeyType(string type) => type.ToLowerInvariant() switch
    {
        "bigint" or "integer" or "int" or "uuid" or "text" => type.ToLowerInvariant(),
        _ => throw new ArgumentException($"Key type '{type}' is not supported (bigint, integer, uuid, text).", nameof(type)),
    };
}
