namespace FieldCrypto.DevKms;

public sealed class DevKmsOptions
{
    public const string Section = "DevKms";

    /// <summary>Master key OCIDs this KMS serves. Each starts with one version.</summary>
    public List<string> KeyIds { get; init; } = ["ocid1.key.oc1.dev.fieldcrypto.demo"];

    /// <summary>File holding the master key versions, so a restart keeps the keys. Null keeps them in memory only.</summary>
    public string? StatePath { get; set; }

    /// <summary>
    /// Directory where a fresh client API key is written on first start (client_key.pem, client_key_id.txt) and
    /// trusted. This is what lets <c>docker compose up</c> run with zero manual key setup.
    /// </summary>
    public string? ClientKeyDirectory { get; set; }

    /// <summary>Additional trusted signing keys: signature keyId to public key PEM.</summary>
    public Dictionary<string, string> TrustedKeys { get; init; } = [];

    public TimeSpan MaxClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Optional delay added to every crypto call, to see how an application behaves when the KMS is a network hop away.
    /// Zero by default; benchmark results say when it was set.
    /// </summary>
    public TimeSpan SimulatedLatency { get; set; } = TimeSpan.Zero;
}
