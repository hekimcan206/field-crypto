namespace FieldCrypto.Kms;

/// <summary>
/// The key encryption key (KEK) side of envelope encryption: a KMS that wraps and unwraps data keys and never
/// hands out its own key material. Implementations: <see cref="LocalKeyEncryptionService"/> (development and tests)
/// and <c>FieldCrypto.Oci.OciVaultKeyEncryptionService</c> (OCI Vault).
/// </summary>
/// <remarks>
/// Both synchronous and asynchronous members exist because EF Core value converters are synchronous. A synchronous
/// implementation must be genuinely synchronous (for HTTP: <c>HttpClient.Send</c>), never sync-over-async.
/// </remarks>
public interface IKeyEncryptionService
{
    /// <summary>Stable identifier of the KEK (an OCID for OCI Vault). Stored with every wrapped data key.</summary>
    string KeyId { get; }

    /// <summary>The version new wraps use. Data keys wrapped under any other version are rewrap candidates.</summary>
    Task<string> GetCurrentKeyVersionAsync(CancellationToken cancellationToken = default);

    Task<WrappedDataKey> WrapAsync(ReadOnlyMemory<byte> plaintextKey, KeyWrapContext context, CancellationToken cancellationToken = default);

    WrappedDataKey Wrap(ReadOnlySpan<byte> plaintextKey, KeyWrapContext context);

    /// <summary>Unwraps a key produced by any version of this KEK that has not been destroyed.</summary>
    Task<byte[]> UnwrapAsync(ReadOnlyMemory<byte> wrappedKey, KeyWrapContext context, CancellationToken cancellationToken = default);

    byte[] Unwrap(ReadOnlySpan<byte> wrappedKey, KeyWrapContext context);
}

/// <param name="KeyVersion">KEK version that produced <paramref name="Ciphertext"/>.</param>
/// <param name="Ciphertext">Opaque to this library; only the KMS that produced it can unwrap it.</param>
public sealed record WrappedDataKey(string KeyVersion, byte[] Ciphertext);

/// <summary>
/// Associated data for the wrap: the data key id and purpose. A wrapped key copied onto another key id (by someone
/// with write access to the key table) no longer unwraps.
/// </summary>
public readonly record struct KeyWrapContext(Guid DataKeyId, string Purpose)
{
    public const string DataKeyIdName = "fc-data-key-id";
    public const string PurposeName = "fc-purpose";

    public IReadOnlyDictionary<string, string> ToAssociatedData() => new SortedDictionary<string, string>(StringComparer.Ordinal)
    {
        [DataKeyIdName] = DataKeyId.ToString("D"),
        [PurposeName] = Purpose,
    };
}
