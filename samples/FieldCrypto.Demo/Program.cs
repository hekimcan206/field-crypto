using System.Globalization;
using FieldCrypto.Demo;
using FieldCrypto.Oci;
using Npgsql;

// docker compose up runs this against PostgreSQL and the development KMS (OCI Vault API). Configuration via environment.
var connectionString = Environment.GetEnvironmentVariable("FC_POSTGRES") ?? "Host=localhost;Port=58962;Database=clinic;Username=clinic;Password=clinic-dev-only";
var kmsUrl = new Uri(Environment.GetEnvironmentVariable("FC_KMS_URL") ?? "http://localhost:58961");
var keyDirectory = Environment.GetEnvironmentVariable("FC_KMS_CLIENT_KEY_DIR") ?? ".devkms";
var keyOcid = Environment.GetEnvironmentVariable("FC_KMS_KEY_OCID") ?? "ocid1.key.oc1.dev.fieldcrypto.demo";
var patients = int.Parse(Environment.GetEnvironmentVariable("FC_PATIENTS") ?? "2000", CultureInfo.InvariantCulture);

CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(10));
var keyPath = Path.Combine(keyDirectory, "client_key.pem");
var keyIdPath = Path.Combine(keyDirectory, "client_key_id.txt");
await WaitFor(() => Task.FromResult(File.Exists(keyPath) && File.Exists(keyIdPath)), "development KMS client key", cancellation.Token);

// The key id file is "tenancy/user/fingerprint"; the fingerprint is recomputed from the key itself.
var parts = File.ReadAllText(keyIdPath).Trim().Split('/');
using var apiKey = OciApiKey.FromPem(parts[0], parts[1], File.ReadAllText(keyPath));
var kms = OciVaultKeyEncryptionService.Create(new OciVaultOptions { CryptoEndpoint = kmsUrl, ManagementEndpoint = kmsUrl, KeyId = keyOcid }, apiKey);

await using var dataSource = NpgsqlDataSource.Create(connectionString);
await WaitFor(async () =>
{
    try
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellation.Token);
        await kms.GetCurrentKeyVersionAsync(cancellation.Token);
        return true;
    }
    catch (Exception ex) when (ex is NpgsqlException or HttpRequestException or OciVaultException)
    {
        return false;
    }
}, "PostgreSQL and the development KMS", cancellation.Token);

Console.WriteLine("FieldCrypto demo. All data is synthetic; no real personal or health data.");
var summary = await new DemoRunner(dataSource, kms, kms.CreateKeyVersionAsync, Console.Out)
    .RunAsync(new DemoOptions(Patients: patients), cancellation.Token);
return summary.Failures.Count == 0 ? 0 : 1;

static async Task WaitFor(Func<Task<bool>> ready, string what, CancellationToken cancellationToken)
{
    for (var attempt = 0; !await ready(); attempt++)
    {
        if (attempt % 10 == 0)
        {
            Console.WriteLine($"waiting for {what}...");
        }

        await Task.Delay(500, cancellationToken);
    }
}
