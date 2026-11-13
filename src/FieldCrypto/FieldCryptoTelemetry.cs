using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace FieldCrypto;

/// <summary>
/// Meter and activity source names to register with OpenTelemetry (<c>AddMeter</c>, <c>AddSource</c>).
/// KMS calls are the expensive, rate-limited and billed part of envelope encryption, so they are counted and traced;
/// field encryptions are not traced individually (one span per column value would drown the trace).
/// </summary>
public static class FieldCryptoTelemetry
{
    public const string Name = "FieldCrypto";

    internal static readonly ActivitySource ActivitySource = new(Name);
    internal static readonly Meter Meter = new(Name);

    internal static readonly Counter<long> KmsCalls =
        Meter.CreateCounter<long>("fieldcrypto.kms.calls", description: "Wrap and unwrap calls sent to the KMS.");

    internal static readonly Counter<long> DataKeyLookups =
        Meter.CreateCounter<long>("fieldcrypto.datakey.lookups", description: "Data key lookups by result (hit, miss).");

    internal static readonly Counter<long> DataKeysCreated =
        Meter.CreateCounter<long>("fieldcrypto.datakey.created", description: "Data keys generated and wrapped.");
}
