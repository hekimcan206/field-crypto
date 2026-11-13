namespace FieldCrypto.Keys;

public enum DataKeyPurpose
{
    /// <summary>AES-256-GCM key for field values.</summary>
    Data = 1,

    /// <summary>Root key from which per-column blind index keys are derived.</summary>
    BlindIndex = 2,
}

/// <summary>
/// One wrapped data key. Ciphertexts reference it by <see cref="Id"/> (16 bytes) instead of carrying the wrapped
/// key inline, so a KEK rotation rewrites these records and nothing else.
/// </summary>
/// <param name="RetiredAt">Set when the key may no longer encrypt; rows using it are re-encryption candidates.</param>
public sealed record DataKeyRecord(
    Guid Id,
    DataKeyPurpose Purpose,
    string KekId,
    string KekVersion,
    byte[] WrappedKey,
    DateTimeOffset CreatedAt,
    DateTimeOffset? RetiredAt = null)
{
    internal string PurposeName => Purpose == DataKeyPurpose.Data ? "data" : "blind-index";
}
