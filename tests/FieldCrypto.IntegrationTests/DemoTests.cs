using FieldCrypto.Demo;
using FieldCrypto.IntegrationTests.Infrastructure;
using FieldCrypto.Kms;

namespace FieldCrypto.IntegrationTests;

/// <summary>The docker compose demo's scenario, run against Testcontainers PostgreSQL, with both KMS implementations.</summary>
public sealed class DemoTests(PostgresEnvironment postgres)
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Demo_passes_every_check_with_the_local_kms()
    {
        var kms = LocalKeyEncryptionService.CreateEphemeral();
        await using var db = await postgres.CreateDatabaseAsync(kms);
        using var output = new StringWriter();

        var summary = await new DemoRunner(db.DataSource, kms, _ => Task.FromResult(kms.Rotate()), output)
            .RunAsync(new DemoOptions(Patients: 1000, LabResults: 50), Ct);

        summary.Failures.Should().BeEmpty(output.ToString());
        summary.PlaintextHits.Should().Be(0);
        summary.CrossColumnCopyDetected.Should().BeTrue();
        summary.RowCopyDetectedDapper.Should().BeTrue();
        summary.RowCopyDetectedEfCore.Should().BeFalse();
        summary.DataRowsChangedByKekRotation.Should().Be(0);
        summary.RowsReencrypted.Should().Be(1050);
        summary.RowsLeftOnRetiredKeys.Should().Be(0);
    }

    [Fact]
    public async Task Demo_passes_every_check_against_the_oci_vault_api()
    {
        await using var kmsHost = new FieldCrypto.UnitTests.Oci.DevKmsFixture();
        await kmsHost.InitializeAsync();
        var kms = kmsHost.CreateService();
        await using var db = await postgres.CreateDatabaseAsync(kms);
        using var output = new StringWriter();

        var summary = await new DemoRunner(db.DataSource, kms, kms.CreateKeyVersionAsync, output)
            .RunAsync(new DemoOptions(Patients: 600, LabResults: 30, MaxMessagesPerDataKey: 400), Ct);

        summary.Failures.Should().BeEmpty(output.ToString());
        summary.KekRewrapped.Should().Be(summary.DataKeys + 1, "every data key plus the blind index root key");
        output.ToString().Should().Contain("rewrapped").And.Contain("data rows changed: 0");
    }
}
