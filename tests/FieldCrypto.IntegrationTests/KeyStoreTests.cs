using FieldCrypto.BlindIndexing;
using FieldCrypto.Dapper;
using FieldCrypto.IntegrationTests.Infrastructure;
using FieldCrypto.Keys;
using FieldCrypto.Kms;

namespace FieldCrypto.IntegrationTests;

public sealed class KeyStoreTests(PostgresEnvironment postgres)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static DataKeyRecord Record(Guid? id = null) =>
        new(id ?? Guid.CreateVersion7(), DataKeyPurpose.Data, "kek", "1", [1, 2, 3], DateTimeOffset.UtcNow.AddMinutes(-1));

    [Fact]
    public async Task Stores_finds_and_lists_records_through_both_paths()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var first = Record();
        var second = Record();

        (await db.Store.TryInsertAsync(first, Ct)).Should().BeTrue();
        db.Store.TryInsert(second).Should().BeTrue();

        var found = await db.Store.FindAsync(first.Id, Ct);
        found!.WrappedKey.Should().Equal(1, 2, 3);
        found.CreatedAt.Should().BeCloseTo(first.CreatedAt, TimeSpan.FromMilliseconds(1));
        db.Store.Find(second.Id)!.Purpose.Should().Be(DataKeyPurpose.Data);
        (await db.Store.ListAsync(Ct)).Select(r => r.Id).Should().Equal(first.Id, second.Id);
        (await db.Store.FindAsync(Guid.NewGuid(), Ct)).Should().BeNull();
    }

    [Fact]
    public async Task Duplicate_insert_returns_false_instead_of_overwriting()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var record = Record();
        await db.Store.TryInsertAsync(record, Ct);

        (await db.Store.TryInsertAsync(record with { WrappedKey = [9] }, Ct)).Should().BeFalse();
        (await db.Store.FindAsync(record.Id, Ct))!.WrappedKey.Should().Equal(1, 2, 3);
    }

    [Fact]
    public async Task Rewrap_update_is_compare_and_set_and_retire_is_one_way()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var record = Record();
        await db.Store.TryInsertAsync(record, Ct);

        (await db.Store.TryUpdateWrappingAsync(record.Id, "kek", "1", "kek", "2", [4], Ct)).Should().BeTrue();
        (await db.Store.TryUpdateWrappingAsync(record.Id, "kek", "1", "kek", "3", [5], Ct)).Should().BeFalse("the record is no longer at version 1");
        var at = DateTimeOffset.Parse("2026-11-13T08:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        await db.Store.RetireAsync(record.Id, at, Ct);
        await db.Store.RetireAsync(record.Id, at.AddDays(1), Ct);

        var stored = await db.Store.FindAsync(record.Id, Ct);
        stored!.KekVersion.Should().Be("2");
        stored.RetiredAt.Should().Be(at);
    }

    [Fact]
    public async Task Eight_processes_starting_at_once_agree_on_one_blind_index_key()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var definition = new BlindIndexDefinition("patients", "email", 32);

        var values = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
        {
            using var ring = new KeyRing(db.Kms, new PostgresDataKeyStore(db.DataSource));
            await ring.InitializeAsync(Ct);
            return new BlindIndexer(ring).Compute("ayse@example.test", definition);
        }, Ct)));

        values.Distinct().Should().ContainSingle();
        (await db.Store.ListAsync(Ct)).Count(r => r.Purpose == DataKeyPurpose.BlindIndex).Should().Be(1);
    }

    [Fact]
    public void Identifiers_that_could_inject_sql_are_refused()
    {
        var act = () => new PostgresDataKeyStore(Npgsql.NpgsqlDataSource.Create("Host=localhost"), "keys; DROP TABLE patients");

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task A_kek_rotation_with_the_postgres_store_rewraps_keys_and_old_ciphertexts_still_decrypt()
    {
        var kms = LocalKeyEncryptionService.CreateEphemeral();
        await using var db = await postgres.CreateDatabaseAsync(kms, new KeyRingOptions { MaxMessagesPerDataKey = 10 });
        var context = new EncryptionContext("patients", "phone");
        var ciphertexts = Enumerable.Range(0, 35).Select(i => db.Encryptor.Encrypt($"+90 532 000 00 {i:00}", context)).ToList();

        kms.Rotate();
        var result = await db.Ring.RewrapAsync(Ct);

        result.Rewrapped.Should().Be(4, "35 encryptions at 10 per data key; no blind index was used, so there is no root key yet");
        var (ring, encryptor, _) = db.OtherProcess();
        using (ring)
        {
            ciphertexts.Select((c, i) => encryptor.Decrypt(c, context) == $"+90 532 000 00 {i:00}").Should().AllBeEquivalentTo(true);
        }
    }
}
