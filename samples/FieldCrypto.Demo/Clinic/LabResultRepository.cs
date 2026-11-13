using Dapper;
using FieldCrypto.Dapper;
using Npgsql;

namespace FieldCrypto.Demo.Clinic;

/// <summary>
/// Dapper access to lab results. The note is encrypted with the row id in its context, so the id must exist before
/// the note is written: insert, take the generated id, then set the note (two statements, one transaction).
/// </summary>
public sealed class LabResultRepository(NpgsqlDataSource dataSource, FieldEncryptor encryptor)
{
    public static EncryptionContext NoteContext(long id) => new("lab_results", "note", id.ToString(System.Globalization.CultureInfo.InvariantCulture));

    public async Task<long> AddAsync(Guid patientId, string testCode, string note, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var id = await connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "INSERT INTO lab_results (patient_id, test_code) VALUES (@patientId, @testCode) RETURNING id",
            new { patientId, testCode },
            transaction,
            cancellationToken: cancellationToken));
        var parameters = new DynamicParameters(new { id }).AddEncrypted("note", note, encryptor, NoteContext(id));
        await connection.ExecuteAsync(new CommandDefinition("UPDATE lab_results SET note = @note WHERE id = @id", parameters, transaction, cancellationToken: cancellationToken));
        await transaction.CommitAsync(cancellationToken);
        return id;
    }

    public async Task<IReadOnlyList<LabResult>> ForPatientAsync(Guid patientId, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var rows = await connection.QueryAsync<(long Id, Guid PatientId, string TestCode, byte[]? Note)>(new CommandDefinition(
            "SELECT id, patient_id, test_code, note FROM lab_results WHERE patient_id = @patientId ORDER BY id",
            new { patientId },
            cancellationToken: cancellationToken));
        return [.. rows.Select(r => new LabResult(r.Id, r.PatientId, r.TestCode, encryptor.DecryptOrNull(r.Note, NoteContext(r.Id)) ?? string.Empty))];
    }
}
