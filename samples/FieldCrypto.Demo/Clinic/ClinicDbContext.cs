using FieldCrypto.BlindIndexing;
using FieldCrypto.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Npgsql;

namespace FieldCrypto.Demo.Clinic;

public sealed class ClinicDbContext(DbContextOptions<ClinicDbContext> options, FieldEncryptor encryptor) : DbContext(options)
{
    public DbSet<Patient> Patients => Set<Patient>();

    internal FieldEncryptor Encryptor { get; } = encryptor;

    public static DbContextOptions<ClinicDbContext> Options(NpgsqlDataSource dataSource, BlindIndexer indexer) =>
        new DbContextOptionsBuilder<ClinicDbContext>()
            .UseNpgsql(dataSource)
            .AddInterceptors(new BlindIndexInterceptor(indexer))
            // The value converters capture the encryptor, so the cached model must be per encryptor (one per key ring).
            .ReplaceService<IModelCacheKeyFactory, PerEncryptorModelCacheKeyFactory>()
            .Options;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Patient>(patient =>
        {
            patient.ToTable("patients");
            patient.HasKey(p => p.Id);
            patient.Property(p => p.Id).HasColumnName("id");
            patient.Property(p => p.NationalId).HasColumnName("national_id").IsEncrypted(Encryptor);
            patient.Property(p => p.NationalIdIndex).HasColumnName("national_id_index");
            patient.Property(p => p.FullName).HasColumnName("full_name").IsEncrypted(Encryptor);
            patient.Property(p => p.Surname).HasColumnName("surname").IsEncrypted(Encryptor);
            patient.Property(p => p.SurnameIndex).HasColumnName("surname_index");
            patient.Property(p => p.Email).HasColumnName("email").IsEncrypted(Encryptor);
            patient.Property(p => p.EmailIndex).HasColumnName("email_index");
            patient.Property(p => p.Phone).HasColumnName("phone").IsEncrypted(Encryptor);
            patient.Property(p => p.BirthYear).HasColumnName("birth_year");
            patient.Property(p => p.CreatedAt).HasColumnName("created_at");
            patient.HasBlindIndex(p => p.NationalId, p => p.NationalIdIndex, ClinicIndexes.NationalId);
            patient.HasBlindIndex(p => p.Surname, p => p.SurnameIndex, ClinicIndexes.Surname);
            patient.HasBlindIndex(p => p.Email, p => p.EmailIndex, ClinicIndexes.Email);
        });
    }

    private sealed class PerEncryptorModelCacheKeyFactory : IModelCacheKeyFactory
    {
        public object Create(DbContext context, bool designTime) =>
            (context.GetType(), ((ClinicDbContext)context).Encryptor, designTime);
    }
}
