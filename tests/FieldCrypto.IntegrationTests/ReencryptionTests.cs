using Dapper;
using FieldCrypto.Dapper;
using FieldCrypto.Demo.Clinic;
using FieldCrypto.IntegrationTests.Infrastructure;
using FieldCrypto.Keys;
using Microsoft.EntityFrameworkCore;

namespace FieldCrypto.IntegrationTests;

public sealed class ReencryptionTests(PostgresEnvironment postgres)
{
    private static readonly DateTimeOffset Created = DateTimeOffset.Parse("2026-11-13T09:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    private static readonly ReencryptionTarget Patients = new(
        "patients", "id", "uuid", [new("national_id", false), new("full_name", false), new("surname", false), new("email", false), new("phone", false)]);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<List<Patient>> SeedAsync(TestDatabase db, int count)
    {
        var patients = SyntheticPatients.Generate(count, seed: 21, Created);
        foreach (var chunk in patients.Chunk(500))
        {
            await using var context = db.Clinic();
            context.Patients.AddRange(chunk);
            await context.SaveChangesAsync(Ct);
        }

        return patients;
    }

    private static async Task<List<Guid>> RetireAllDataKeysAsync(TestDatabase db)
    {
        var keys = (await db.Store.ListAsync(Ct)).Where(k => k.Purpose == DataKeyPurpose.Data).Select(k => k.Id).ToList();
        foreach (var key in keys)
        {
            await db.Ring.RetireDataKeyAsync(key, Ct);
        }

        return keys;
    }

    private static async Task<long> RowsOnAsync(TestDatabase db, IEnumerable<Guid> keys)
    {
        var ids = keys.Select(k =>
        {
            var bytes = new byte[16];
            k.TryWriteBytes(bytes, bigEndian: true, out _);
            return bytes;
        }).ToArray();
        await using var connection = await db.DataSource.OpenConnectionAsync(Ct);
        return await connection.ExecuteScalarAsync<long>(
            "SELECT count(*) FROM patients WHERE substring(national_id from 2 for 16) = ANY(@ids) OR substring(phone from 2 for 16) = ANY(@ids) OR substring(email from 2 for 16) = ANY(@ids)",
            new { ids });
    }

    [Fact]
    public async Task Moves_every_value_off_retired_keys_and_nothing_changes_for_readers()
    {
        await using var db = await postgres.CreateDatabaseAsync(options: new KeyRingOptions { MaxMessagesPerDataKey = 700 });
        var patients = await SeedAsync(db, 1000);
        var retired = await RetireAllDataKeysAsync(db);

        var result = await new ColumnReencryptor(db.DataSource, db.Encryptor).ReencryptRetiredAsync(Patients, batchSize: 128, Ct);

        result.RowsReencrypted.Should().Be(1000);
        result.Conflicts.Should().Be(0);
        result.Batches.Should().Be(8);
        (await RowsOnAsync(db, retired)).Should().Be(0);
        var (ring, encryptor, indexer) = db.OtherProcess();
        using (ring)
        await using (var read = new ClinicDbContext(ClinicDbContext.Options(db.DataSource, indexer), encryptor))
        {
            var loaded = await read.Patients.AsNoTracking().OrderBy(p => p.Id).ToListAsync(Ct);
            loaded.Select(p => (p.NationalId, p.Email, p.Phone)).Should().Equal(patients.OrderBy(p => p.Id).Select(p => (p.NationalId, p.Email, p.Phone)));
        }
    }

    [Fact]
    public async Task A_second_run_finds_nothing_to_do()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        await SeedAsync(db, 50);
        await RetireAllDataKeysAsync(db);
        var reencryptor = new ColumnReencryptor(db.DataSource, db.Encryptor);
        await reencryptor.ReencryptRetiredAsync(Patients, cancellationToken: Ct);

        var second = await reencryptor.ReencryptRetiredAsync(Patients, cancellationToken: Ct);

        second.RowsExamined.Should().Be(0);
    }

    [Fact]
    public async Task Refuses_to_reencrypt_onto_the_key_it_is_moving_away_from()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        await SeedAsync(db, 5);

        var act = () => new ColumnReencryptor(db.DataSource, db.Encryptor).ReencryptAsync(Patients, [db.Ring.ActiveDataKeyId!.Value], cancellationToken: Ct);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task Concurrent_application_writes_are_never_overwritten()
    {
        await using var db = await postgres.CreateDatabaseAsync(options: new KeyRingOptions { MaxMessagesPerDataKey = 2000 });
        var patients = await SeedAsync(db, 3000);
        var retired = await RetireAllDataKeysAsync(db);
        var finalPhones = new Dictionary<Guid, string>();
        using var stop = new CancellationTokenSource();

        // The application keeps updating phones (through EF Core, new values go to the new active key) while the job runs.
        var writer = Task.Run(async () =>
        {
            var random = new Random(7);
            var round = 0;
            while (!stop.IsCancellationRequested || round < 20)
            {
                round++;
                var batch = Enumerable.Range(0, 25).Select(_ => patients[random.Next(patients.Count)].Id).Distinct().ToList();
                await using var context = db.Clinic();
                var rows = await context.Patients.Where(p => batch.Contains(p.Id)).ToListAsync(CancellationToken.None);
                foreach (var row in rows)
                {
                    row.Phone = $"+90 555 {round:000} {random.Next(10, 99)} {random.Next(10, 99)}";
                    lock (finalPhones)
                    {
                        finalPhones[row.Id] = row.Phone;
                    }
                }

                await context.SaveChangesAsync(CancellationToken.None);
            }
        }, Ct);

        var result = await new ColumnReencryptor(db.DataSource, db.Encryptor).ReencryptRetiredAsync(Patients, batchSize: 50, Ct);
        await stop.CancelAsync();
        await writer;
        var cleanup = await new ColumnReencryptor(db.DataSource, db.Encryptor).ReencryptRetiredAsync(Patients, cancellationToken: Ct);

        TestContext.Current.SendDiagnosticMessage($"first pass: {result}; cleanup: {cleanup}");
        (result.RowsReencrypted + result.Conflicts).Should().Be(result.RowsExamined);
        (await RowsOnAsync(db, retired)).Should().Be(0);
        await using var read = db.Clinic();
        var stored = await read.Patients.AsNoTracking().ToDictionaryAsync(p => p.Id, p => p.Phone, Ct);
        finalPhones.Should().NotBeEmpty();
        finalPhones.Should().OnlyContain(kv => stored[kv.Key] == kv.Value, "the last application write wins over the job");
    }

    [Fact]
    public async Task Row_bound_columns_are_reencrypted_with_their_row_key()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patients = await SeedAsync(db, 3);
        var labs = new LabResultRepository(db.DataSource, db.Encryptor);
        foreach (var patient in patients)
        {
            await labs.AddAsync(patient.Id, "LDL", $"LDL for {patient.Id} (synthetic)", Ct);
        }

        await RetireAllDataKeysAsync(db);
        var result = await new ColumnReencryptor(db.DataSource, db.Encryptor).ReencryptRetiredAsync(new ReencryptionTarget("lab_results", "id", "bigint", [new("note", true)]), cancellationToken: Ct);

        result.RowsReencrypted.Should().Be(3);
        foreach (var patient in patients)
        {
            (await labs.ForPatientAsync(patient.Id, Ct)).Single().Note.Should().Be($"LDL for {patient.Id} (synthetic)");
        }
    }
}
