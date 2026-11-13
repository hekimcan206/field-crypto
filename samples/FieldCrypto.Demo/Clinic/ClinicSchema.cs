using FieldCrypto.Dapper;
using Npgsql;

namespace FieldCrypto.Demo.Clinic;

/// <summary>Schema for the demo, tests and benchmarks. Encrypted columns are bytea; blind indexes are bigint with a b-tree.</summary>
public static class ClinicSchema
{
    public static readonly string Sql = PostgresDataKeyStore.CreateTableSql() + """

        CREATE TABLE IF NOT EXISTS patients (
            id                 uuid        PRIMARY KEY,
            national_id        bytea       NOT NULL,
            national_id_index  bigint      NULL,
            full_name          bytea       NOT NULL,
            surname            bytea       NOT NULL,
            surname_index      bigint      NULL,
            email              bytea       NULL,
            email_index        bigint      NULL,
            phone              bytea       NULL,
            birth_year         integer     NOT NULL,
            created_at         timestamptz NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_patients_national_id_index ON patients (national_id_index);
        CREATE INDEX IF NOT EXISTS ix_patients_surname_index ON patients (surname_index);
        CREATE INDEX IF NOT EXISTS ix_patients_email_index ON patients (email_index);

        CREATE TABLE IF NOT EXISTS lab_results (
            id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            patient_id  uuid   NOT NULL REFERENCES patients (id),
            test_code   text   NOT NULL,
            note        bytea  NULL
        );
        """;

    public static async Task CreateAsync(NpgsqlDataSource dataSource, CancellationToken cancellationToken = default)
    {
        await using var command = dataSource.CreateCommand(Sql);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
