using Dapper;
using FieldCrypto.Dapper;
using FieldCrypto.Demo.Clinic;
using FieldCrypto.IntegrationTests.Infrastructure;

namespace FieldCrypto.IntegrationTests;

public sealed class DapperTests(PostgresEnvironment postgres)
{
    private static readonly DateTimeOffset Created = DateTimeOffset.Parse("2026-11-13T09:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<List<Patient>> SeedAsync(TestDatabase db, int count)
    {
        var patients = SyntheticPatients.Generate(count, seed: 11, Created);
        await using var context = db.Clinic();
        context.Patients.AddRange(patients);
        await context.SaveChangesAsync(Ct);
        return patients;
    }

    [Fact]
    public async Task Row_bound_notes_round_trip()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patient = (await SeedAsync(db, 1))[0];
        var labs = new LabResultRepository(db.DataSource, db.Encryptor);

        await labs.AddAsync(patient.Id, "HBA1C", "HbA1c %6.1 (synthetic)", Ct);
        await labs.AddAsync(patient.Id, "LDL", "LDL 131 mg/dL (synthetic)", Ct);

        (await labs.ForPatientAsync(patient.Id, Ct)).Select(r => r.Note).Should().Equal("HbA1c %6.1 (synthetic)", "LDL 131 mg/dL (synthetic)");
    }

    [Fact]
    public async Task A_note_copied_to_another_row_is_detected()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patient = (await SeedAsync(db, 1))[0];
        var labs = new LabResultRepository(db.DataSource, db.Encryptor);
        var first = await labs.AddAsync(patient.Id, "HBA1C", "normal", Ct);
        var second = await labs.AddAsync(patient.Id, "HBA1C", "critical", Ct);

        await using var connection = await db.DataSource.OpenConnectionAsync(Ct);
        await connection.ExecuteAsync("UPDATE lab_results SET note = (SELECT note FROM lab_results WHERE id = @first) WHERE id = @second", new { first, second });

        var act = () => labs.ForPatientAsync(patient.Id, Ct);
        (await act.Should().ThrowAsync<FieldDecryptionException>()).Which.Failure.Should().Be(FieldDecryptionFailure.AuthenticationFailed);
    }

    [Fact]
    public async Task Blind_index_parameter_finds_rows_written_by_ef_core()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patients = await SeedAsync(db, 200);
        var target = patients[17];

        await using var connection = await db.DataSource.OpenConnectionAsync(Ct);
        var parameters = new DynamicParameters().AddBlindIndex("index", target.NationalId, db.Indexer, ClinicIndexes.NationalId);
        var rows = await connection.QueryAsync<(Guid Id, byte[] NationalId)>("SELECT id, national_id FROM patients WHERE national_id_index = @index", parameters);

        var matches = rows.Where(r => db.Encryptor.Decrypt(r.NationalId, new EncryptionContext("patients", "national_id")) == target.NationalId).ToList();
        matches.Should().ContainSingle().Which.Id.Should().Be(target.Id);
    }

    [Fact]
    public async Task Null_parameters_stay_sql_null()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        await using var connection = await db.DataSource.OpenConnectionAsync(Ct);

        var parameters = new DynamicParameters()
            .AddEncrypted("value", null, db.Encryptor, new EncryptionContext("t", "c"))
            .AddBlindIndex("index", null, db.Indexer, ClinicIndexes.Email);
        var (value, index) = await connection.QuerySingleAsync<(byte[]? Value, long? Index)>("SELECT @value::bytea, @index::bigint", parameters);

        value.Should().BeNull();
        index.Should().BeNull();
        db.Encryptor.DecryptOrNull(null, new EncryptionContext("t", "c")).Should().BeNull();
    }
}
