using Dapper;
using FieldCrypto.BlindIndexing;
using FieldCrypto.Demo.Clinic;
using FieldCrypto.EntityFrameworkCore;
using FieldCrypto.IntegrationTests.Infrastructure;
using Microsoft.EntityFrameworkCore;

namespace FieldCrypto.IntegrationTests;

public sealed class EfCoreTests(PostgresEnvironment postgres)
{
    private static readonly DateTimeOffset Created = DateTimeOffset.Parse("2026-11-13T09:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Round_trips_encrypted_properties_and_keeps_nulls_null()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patients = SyntheticPatients.Generate(50, seed: 1, Created);
        await using (var context = db.Clinic())
        {
            context.Patients.AddRange(patients);
            await context.SaveChangesAsync(Ct);
        }

        await using var read = db.Clinic();
        var loaded = await read.Patients.AsNoTracking().OrderBy(p => p.Id).ToListAsync(Ct);

        loaded.Should().BeEquivalentTo(patients.OrderBy(p => p.Id), o => o.Excluding(p => p.NationalIdIndex).Excluding(p => p.SurnameIndex).Excluding(p => p.EmailIndex));
        await using var connection = await db.DataSource.OpenConnectionAsync(Ct);
        var nullEmails = await connection.ExecuteScalarAsync<int>("SELECT count(*) FROM patients WHERE email IS NULL AND email_index IS NULL");
        nullEmails.Should().Be(patients.Count(p => p.Email is null));
    }

    [Fact]
    public async Task Blind_index_columns_follow_inserts_and_updates()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patient = SyntheticPatients.Generate(1, seed: 2, Created)[0];
        await using (var context = db.Clinic())
        {
            context.Patients.Add(patient);
            await context.SaveChangesAsync(Ct);
            patient.Email = "yeni.adres@example.test";
            await context.SaveChangesAsync(Ct);
        }

        await using var read = db.Clinic();
        var stored = await read.Patients.AsNoTracking().SingleAsync(Ct);
        stored.EmailIndex.Should().Be(db.Indexer.Compute("YENI.ADRES@example.test", ClinicIndexes.Email));
        stored.NationalIdIndex.Should().Be(db.Indexer.Compute(patient.NationalId, ClinicIndexes.NationalId));
        (await read.Patients.WhereBlindIndexMatchesAsync(db.Indexer, p => p.Email, "yeni.adres@example.test", cancellationToken: Ct)).Matches.Should().ContainSingle();
    }

    [Fact]
    public async Task Turkish_surname_search_matches_every_spelling_people_type()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patients = SyntheticPatients.Generate(600, seed: 3, Created);
        await using (var context = db.Clinic())
        {
            context.Patients.AddRange(patients);
            await context.SaveChangesAsync(Ct);
        }

        await using var read = db.Clinic();
        foreach (var (stored, typed) in new[] { ("Işık", "IŞIK"), ("İnce", "INCE"), ("Irmak", "ırmak"), ("Ilgaz", "ılgaz"), ("İpek", "ipek") })
        {
            var result = await read.Patients.WhereBlindIndexMatchesAsync(db.Indexer, p => p.Surname, typed, cancellationToken: Ct);
            result.Matches.Should().HaveCount(patients.Count(p => p.Surname == stored), $"\"{typed}\" should find every {stored}");
            result.Matches.Should().OnlyContain(p => p.Surname == stored);
        }
    }

    [Fact]
    public async Task Equality_filter_on_an_encrypted_property_finds_nothing_which_is_why_blind_indexes_exist()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patient = SyntheticPatients.Generate(1, seed: 4, Created)[0];
        await using (var context = db.Clinic())
        {
            context.Patients.Add(patient);
            await context.SaveChangesAsync(Ct);
        }

        await using var read = db.Clinic();
        (await read.Patients.Where(p => p.NationalId == patient.NationalId).ToListAsync(Ct)).Should().BeEmpty("every encryption uses a fresh nonce");
        (await read.Patients.WhereBlindIndexMatchesAsync(db.Indexer, p => p.NationalId, patient.NationalId, cancellationToken: Ct)).Matches.Should().ContainSingle();
    }

    [Fact]
    public async Task Ciphertext_copied_to_another_column_fails_but_to_another_row_of_the_same_column_decrypts()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        var patients = SyntheticPatients.Generate(2, seed: 5, Created);
        await using (var context = db.Clinic())
        {
            context.Patients.AddRange(patients);
            await context.SaveChangesAsync(Ct);
        }

        await using var connection = await db.DataSource.OpenConnectionAsync(Ct);
        await connection.ExecuteAsync("UPDATE patients SET full_name = (SELECT national_id FROM patients WHERE id = @a) WHERE id = @b", new { a = patients[0].Id, b = patients[1].Id });
        await using (var read = db.Clinic())
        {
            var act = () => read.Patients.AsNoTracking().SingleAsync(p => p.Id == patients[1].Id, Ct);
            (await act.Should().ThrowAsync<FieldDecryptionException>()).Which.Failure.Should().Be(FieldDecryptionFailure.AuthenticationFailed);
        }

        await connection.ExecuteAsync("UPDATE patients SET national_id = (SELECT national_id FROM patients WHERE id = @a), full_name = (SELECT full_name FROM patients WHERE id = @a) WHERE id = @b", new { a = patients[0].Id, b = patients[1].Id });
        await using (var read = db.Clinic())
        {
            var swapped = await read.Patients.AsNoTracking().SingleAsync(p => p.Id == patients[1].Id, Ct);
            swapped.NationalId.Should().Be(patients[0].NationalId, "EF Core values are column-bound: a same-column row copy is not detected (documented limitation)");
        }
    }

    [Fact]
    public async Task Synchronous_save_and_query_work_end_to_end_over_the_oci_vault_api()
    {
        await using var kms = new FieldCrypto.UnitTests.Oci.DevKmsFixture();
        await kms.InitializeAsync();
        await using var db = await postgres.CreateDatabaseAsync(kms.CreateService());
        var patients = SyntheticPatients.Generate(20, seed: 6, Created);

        using (var context = db.Clinic())
        {
            context.Patients.AddRange(patients);
            context.SaveChanges();
        }

        var (ring, encryptor, indexer) = db.OtherProcess();
        using (ring)
        await using (var read = new ClinicDbContext(ClinicDbContext.Options(db.DataSource, indexer), encryptor))
        {
            read.Patients.AsNoTracking().OrderBy(p => p.Id).Select(p => p.NationalId).ToList()
                .Should().Equal(patients.OrderBy(p => p.Id).Select(p => p.NationalId));
            ring.Statistics.KmsUnwraps.Should().Be(1, "one data key for 20 patients, unwrapped once by the synchronous HTTP path");
        }
    }

    [Fact]
    public async Task Coarse_index_returns_false_positives_that_the_lookup_filters_out()
    {
        await using var db = await postgres.CreateDatabaseAsync();
        await using var connection = await db.DataSource.OpenConnectionAsync(Ct);
        await connection.ExecuteAsync("CREATE TABLE contacts (id uuid PRIMARY KEY, name bytea NOT NULL, name_index bigint)");
        var names = Enumerable.Range(0, 300).Select(i => $"Kişi {i:000}").ToList();
        await using (var context = new ContactsContext(db))
        {
            context.Contacts.AddRange(names.Select(n => new Contact { Id = Guid.NewGuid(), Name = n }));
            await context.SaveChangesAsync(Ct);
        }

        await using var read = new ContactsContext(db);
        var result = await read.Contacts.WhereBlindIndexMatchesAsync(db.Indexer, c => c.Name, "KİŞİ 123", cancellationToken: Ct);

        result.Matches.Should().ContainSingle().Which.Name.Should().Be("Kişi 123");
        result.FalsePositives.Should().BeGreaterThan(5, "300 rows over 16 index values leave ~18 rows per value");
    }

    private sealed class Contact
    {
        public Guid Id { get; set; }

        public string Name { get; set; } = string.Empty;

        public long? NameIndex { get; set; }
    }

    private sealed class ContactsContext(TestDatabase db) : DbContext(
        new DbContextOptionsBuilder<ContactsContext>()
            .UseNpgsql(db.DataSource)
            .AddInterceptors(new BlindIndexInterceptor(db.Indexer))
            .ReplaceService<Microsoft.EntityFrameworkCore.Infrastructure.IModelCacheKeyFactory, PerInstanceModelCacheKey>()
            .Options)
    {
        public static readonly BlindIndexDefinition NameIndex = new("contacts", "name", 4, TextNormalizers.TurkishCaseFold);

        public DbSet<Contact> Contacts => Set<Contact>();

        public FieldEncryptor Encryptor { get; } = db.Encryptor;

        protected override void OnModelCreating(ModelBuilder modelBuilder) => modelBuilder.Entity<Contact>(c =>
        {
            c.ToTable("contacts");
            c.Property(x => x.Id).HasColumnName("id");
            c.Property(x => x.Name).HasColumnName("name").IsEncrypted(Encryptor);
            c.Property(x => x.NameIndex).HasColumnName("name_index");
            c.HasBlindIndex(x => x.Name, x => x.NameIndex, NameIndex);
        });
    }

    private sealed class PerInstanceModelCacheKey : Microsoft.EntityFrameworkCore.Infrastructure.IModelCacheKeyFactory
    {
        public object Create(DbContext context, bool designTime) => (context.GetType(), ((ContactsContext)context).Encryptor, designTime);
    }
}
