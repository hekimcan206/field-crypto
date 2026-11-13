using System.Diagnostics;
using System.Text.Json;
using Dapper;
using FieldCrypto.BlindIndexing;
using FieldCrypto.Dapper;
using FieldCrypto.Demo.Clinic;
using FieldCrypto.EntityFrameworkCore;
using FieldCrypto.Keys;
using FieldCrypto.Kms;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace FieldCrypto.Demo;

public sealed record DemoOptions(int Patients = 2000, int LabResults = 200, long MaxMessagesPerDataKey = 500, int Seed = 2026);

/// <summary>
/// The end-to-end story: seed encrypted patients, show what a DBA sees, search through blind indexes, tamper with
/// ciphertexts, rotate the KEK (no data row changes), retire the data keys and re-encrypt online. Every step checks its
/// own claim and reports a failure instead of printing a happy message.
/// </summary>
public sealed class DemoRunner(NpgsqlDataSource dataSource, IKeyEncryptionService kms, Func<CancellationToken, Task<string>> rotateKek, TextWriter output)
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly List<string> _failures = [];

    public async Task<DemoSummary> RunAsync(DemoOptions options, CancellationToken cancellationToken = default)
    {
        await ClinicSchema.CreateAsync(dataSource, cancellationToken);
        var store = new PostgresDataKeyStore(dataSource);
        using var ring = new KeyRing(kms, store, new KeyRingOptions { MaxMessagesPerDataKey = options.MaxMessagesPerDataKey });
        await ring.InitializeAsync(cancellationToken);
        var encryptor = new FieldEncryptor(ring);
        var indexer = new BlindIndexer(ring);

        Section($"1. Seed {options.Patients:N0} synthetic patients (EF Core) and {options.LabResults:N0} lab results (Dapper)");
        var patients = SyntheticPatients.Generate(options.Patients, options.Seed, DateTimeOffset.UnixEpoch.AddYears(56));
        var stopwatch = Stopwatch.StartNew();
        foreach (var chunk in patients.Chunk(500))
        {
            await using var db = new ClinicDbContext(ClinicDbContext.Options(dataSource, indexer), encryptor);
            db.Patients.AddRange(chunk);
            await db.SaveChangesAsync(cancellationToken);
        }

        var labs = new LabResultRepository(dataSource, encryptor);
        var labIds = new List<long>();
        foreach (var patient in patients.Take(options.LabResults))
        {
            labIds.Add(await labs.AddAsync(patient.Id, "HBA1C", $"HbA1c %{5 + (patient.BirthYear % 40) / 10.0:0.0} (synthetic)", cancellationToken));
        }

        var dataKeys = (await store.ListAsync(cancellationToken)).Count(k => k.Purpose == DataKeyPurpose.Data);
        Line($"seeded in {stopwatch.Elapsed.TotalSeconds:0.0} s; {dataKeys} data keys ({options.MaxMessagesPerDataKey} encryptions each), {ring.Statistics.KmsWraps} KMS wraps");

        Section("2. What a database reader sees");
        await using (var connection = await dataSource.OpenConnectionAsync(cancellationToken))
        {
            var sample = await connection.QuerySingleAsync<(byte[] NationalId, long? Index)>("SELECT national_id AS NationalId, national_id_index AS Index FROM patients ORDER BY id LIMIT 1");
            Line($"national_id = \\x{Convert.ToHexStringLower(sample.NationalId)[..48]}... ({sample.NationalId.Length} bytes), national_id_index = {sample.Index}");
        }

        var plaintextHits = await CountPlaintextHits(patients.Take(100).Select(p => p.NationalId).Concat(patients.Take(100).Select(p => p.Surname)), cancellationToken);
        Check(plaintextHits == 0, $"{plaintextHits} plaintext values found in encrypted columns");
        Line($"searched every encrypted column for 200 known plaintexts: {plaintextHits} hits");

        Section("3. Search through blind indexes");
        var target = patients[options.Patients / 2];
        await using var search = new ClinicDbContext(ClinicDbContext.Options(dataSource, indexer), encryptor);
        var typed = target.NationalId.Insert(3, " ").Insert(7, "-");
        var byId = await search.Patients.WhereBlindIndexMatchesAsync(indexer, p => p.NationalId, typed, cancellationToken: cancellationToken);
        Check(byId.Matches.Count == 1 && byId.Matches[0].Id == target.Id, "national id lookup did not return exactly the target patient");
        Line($"national id \"{typed}\": {byId.Candidates} candidate rows, {byId.Matches.Count} match after decryption ({byId.FalsePositives} false positives, expected ~{BlindIndexPlanner.ExpectedFalsePositives(options.Patients, ClinicIndexes.NationalId.Bits):0.0})");

        var isikCount = patients.Count(p => p.Surname == "Işık");
        var bySurname = await search.Patients.WhereBlindIndexMatchesAsync(indexer, p => p.Surname, "IŞIK", cancellationToken: cancellationToken);
        Check(bySurname.Matches.Count == isikCount, $"surname search found {bySurname.Matches.Count}, expected {isikCount}");
        Line($"surname \"IŞIK\": {bySurname.Matches.Count} patients named Işık ({bySurname.Candidates} candidates)");

        var emailOwner = patients.First(p => p.Email is not null);
        var byEmail = await search.Patients.WhereBlindIndexMatchesAsync(indexer, p => p.Email, "  " + emailOwner.Email!.ToUpperInvariant(), cancellationToken: cancellationToken);
        Check(byEmail.Matches.Count == 1 && byEmail.Matches[0].Id == emailOwner.Id, "e-mail lookup failed");
        Line($"e-mail typed in upper case with spaces: {byEmail.Matches.Count} match ({byEmail.Candidates} candidates)");

        Section("4. Tampering");
        var a = patients[1];
        var b = patients[2];
        var crossColumn = await Tamper(
            $"UPDATE patients SET phone = (SELECT national_id FROM patients WHERE id = '{a.Id}') WHERE id = '{b.Id}'",
            () => ReadPatient(b.Id, encryptor, indexer, cancellationToken),
            $"UPDATE patients SET phone = @old WHERE id = '{b.Id}'",
            $"SELECT phone FROM patients WHERE id = '{b.Id}'",
            cancellationToken);
        Check(crossColumn, "copying a national id ciphertext into another column was not detected");
        Line($"national_id of one patient copied into another patient's phone column: {(crossColumn ? "DETECTED" : "missed")}");

        var rowSwapDapper = await Tamper(
            $"UPDATE lab_results SET note = (SELECT note FROM lab_results WHERE id = {labIds[0]}) WHERE id = {labIds[1]}",
            async () => (object)await labs.ForPatientAsync(patients[1].Id, cancellationToken),
            $"UPDATE lab_results SET note = @old WHERE id = {labIds[1]}",
            $"SELECT note FROM lab_results WHERE id = {labIds[1]}",
            cancellationToken);
        Check(rowSwapDapper, "row-bound note copied to another row was not detected");
        Line($"lab note copied to another row (Dapper, row-bound): {(rowSwapDapper ? "DETECTED" : "missed")}");

        var rowSwapEf = await Tamper(
            $"UPDATE patients SET national_id = (SELECT national_id FROM patients WHERE id = '{a.Id}') WHERE id = '{b.Id}'",
            () => ReadPatient(b.Id, encryptor, indexer, cancellationToken),
            $"UPDATE patients SET national_id = @old WHERE id = '{b.Id}'",
            $"SELECT national_id FROM patients WHERE id = '{b.Id}'",
            cancellationToken);
        Check(!rowSwapEf, "EF Core values are column-bound; a same-column row swap is expected to decrypt");
        Line($"national_id copied to another row (EF Core, column-bound): {(rowSwapEf ? "detected" : "NOT detected, as documented: EF value converters have no row context")}");

        Section("5. KEK rotation: rewrap data keys, touch no data row");
        var before = await DataFingerprint(cancellationToken);
        var newVersion = await rotateKek(cancellationToken);
        stopwatch.Restart();
        var rewrap = await ring.RewrapAsync(cancellationToken);
        var rewrapTime = stopwatch.Elapsed;
        var after = await DataFingerprint(cancellationToken);
        Check(before == after, "data rows changed during a KEK rotation");
        Check(rewrap.Rewrapped == rewrap.Examined && rewrap.Conflicts == 0, $"rewrap incomplete: {rewrap}");
        Line($"new KEK version {newVersion}; rewrapped {rewrap.Rewrapped} of {rewrap.Examined} keys in {rewrapTime.TotalMilliseconds:0} ms; data rows changed: {(before == after ? 0 : -1)}");
        var decryptAfterRewrap = await DecryptEverything(cancellationToken);
        Check(decryptAfterRewrap == options.Patients, "not every patient decrypts after rewrap with a cold cache");
        Line($"cold-cache process decrypted {decryptAfterRewrap:N0} patients after the rotation");

        Section("6. Retire every data key and re-encrypt online");
        var retired = (await store.ListAsync(cancellationToken)).Where(k => k.Purpose == DataKeyPurpose.Data).Select(k => k.Id).ToList();
        await ring.RetireActiveDataKeyAsync(cancellationToken);
        foreach (var id in retired)
        {
            await ring.RetireDataKeyAsync(id, cancellationToken);
        }

        var reencryptor = new ColumnReencryptor(dataSource, encryptor);
        var patientsResult = await reencryptor.ReencryptAsync(
            new ReencryptionTarget("patients", "id", "uuid", [new("national_id", false), new("full_name", false), new("surname", false), new("email", false), new("phone", false)]),
            retired,
            cancellationToken: cancellationToken);
        var labsResult = await reencryptor.ReencryptAsync(new ReencryptionTarget("lab_results", "id", "bigint", [new("note", true)]), retired, cancellationToken: cancellationToken);
        var left = await RowsOnKeys(retired, cancellationToken);
        Check(left == 0, $"{left} rows still reference retired data keys");
        Check(patientsResult.RowsReencrypted == options.Patients && labsResult.RowsReencrypted == options.LabResults, "not every row was re-encrypted");
        Line($"patients: {patientsResult.RowsReencrypted:N0} rows in {patientsResult.Elapsed.TotalSeconds:0.00} s ({patientsResult.RowsPerSecond:N0} rows/s, 5 columns each), conflicts {patientsResult.Conflicts}");
        Line($"lab_results: {labsResult.RowsReencrypted:N0} rows (row-bound), conflicts {labsResult.Conflicts}; rows left on retired keys: {left}");
        var decryptAfterReencrypt = await DecryptEverything(cancellationToken);
        Check(decryptAfterReencrypt == options.Patients, "not every patient decrypts after re-encryption");

        var summary = new DemoSummary(
            options.Patients,
            options.LabResults,
            dataKeys,
            plaintextHits,
            byId.Candidates,
            byId.Matches.Count,
            bySurname.Matches.Count,
            crossColumn,
            rowSwapDapper,
            rowSwapEf,
            rewrap.Rewrapped,
            before == after ? 0 : -1,
            patientsResult.RowsReencrypted + labsResult.RowsReencrypted,
            left,
            [.. _failures]);
        await output.WriteLineAsync();
        await output.WriteLineAsync(JsonSerializer.Serialize(summary, Json));
        return summary;
    }

    private async Task<int> CountPlaintextHits(IEnumerable<string> plaintexts, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        return await connection.ExecuteScalarAsync<int>(new CommandDefinition(
            """
            SELECT count(*) FROM patients p, unnest(@values) AS v(value)
            WHERE position(convert_to(v.value, 'UTF8') IN p.national_id) > 0
               OR position(convert_to(v.value, 'UTF8') IN p.full_name) > 0
               OR position(convert_to(v.value, 'UTF8') IN p.surname) > 0
            """,
            new { values = plaintexts.ToArray() },
            cancellationToken: cancellationToken));
    }

    /// <summary>Applies a tampering statement, tries to read, then restores the original bytes. True when the read failed.</summary>
    private async Task<bool> Tamper(string attack, Func<Task<object>> read, string restore, string capture, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var old = await connection.ExecuteScalarAsync<byte[]?>(new CommandDefinition(capture, cancellationToken: cancellationToken));
        await connection.ExecuteAsync(new CommandDefinition(attack, cancellationToken: cancellationToken));
        try
        {
            await read();
            return false;
        }
        catch (FieldDecryptionException ex) when (ex.Failure == FieldDecryptionFailure.AuthenticationFailed)
        {
            return true;
        }
        finally
        {
            await connection.ExecuteAsync(new CommandDefinition(restore, new { old }, cancellationToken: cancellationToken));
        }
    }

    private async Task<object> ReadPatient(Guid id, FieldEncryptor encryptor, BlindIndexer indexer, CancellationToken cancellationToken)
    {
        await using var db = new ClinicDbContext(ClinicDbContext.Options(dataSource, indexer), encryptor);
        return await db.Patients.AsNoTracking().SingleAsync(p => p.Id == id, cancellationToken);
    }

    private async Task<string> DataFingerprint(CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        return await connection.ExecuteScalarAsync<string>(new CommandDefinition(
            """
            SELECT md5(coalesce((SELECT string_agg(md5(p::text), '' ORDER BY id) FROM patients p), '')
                    || coalesce((SELECT string_agg(md5(l::text), '' ORDER BY id) FROM lab_results l), ''))
            """,
            cancellationToken: cancellationToken)) ?? string.Empty;
    }

    /// <summary>A fresh key ring (cold cache, as in another process) decrypts every patient.</summary>
    private async Task<int> DecryptEverything(CancellationToken cancellationToken)
    {
        using var ring = new KeyRing(kms, new PostgresDataKeyStore(dataSource));
        var encryptor = new FieldEncryptor(ring);
        await using var db = new ClinicDbContext(ClinicDbContext.Options(dataSource, new BlindIndexer(ring)), encryptor);
        var count = 0;
        await foreach (var patient in db.Patients.AsNoTracking().AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            if (SyntheticPatients.IsValidNationalId(patient.NationalId))
            {
                count++;
            }
        }

        return count;
    }

    private async Task<long> RowsOnKeys(IReadOnlyCollection<Guid> keys, CancellationToken cancellationToken)
    {
        var ids = keys.Select(k =>
        {
            var bytes = new byte[16];
            k.TryWriteBytes(bytes, bigEndian: true, out _);
            return bytes;
        }).ToArray();
        await using var command = dataSource.CreateCommand(
            """
            SELECT (SELECT count(*) FROM patients WHERE substring(national_id from 2 for 16) = ANY($1) OR substring(full_name from 2 for 16) = ANY($1)
                       OR substring(surname from 2 for 16) = ANY($1) OR substring(email from 2 for 16) = ANY($1) OR substring(phone from 2 for 16) = ANY($1))
                 + (SELECT count(*) FROM lab_results WHERE substring(note from 2 for 16) = ANY($1))
            """);
        command.Parameters.Add(new NpgsqlParameter { Value = ids, NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Bytea });
        return (long)(await command.ExecuteScalarAsync(cancellationToken))!;
    }

    private void Check(bool condition, string failure)
    {
        if (!condition)
        {
            _failures.Add(failure);
            Line("FAILED: " + failure);
        }
    }

    private void Section(string title)
    {
        output.WriteLine();
        output.WriteLine("=== " + title);
    }

    private void Line(string text) => output.WriteLine("  " + text);
}

public sealed record DemoSummary(
    int Patients,
    int LabResults,
    int DataKeys,
    int PlaintextHits,
    int NationalIdCandidates,
    int NationalIdMatches,
    int SurnameMatches,
    bool CrossColumnCopyDetected,
    bool RowCopyDetectedDapper,
    bool RowCopyDetectedEfCore,
    int KekRewrapped,
    int DataRowsChangedByKekRotation,
    long RowsReencrypted,
    long RowsLeftOnRetiredKeys,
    IReadOnlyList<string> Failures);
