namespace FieldCrypto.Keys;

/// <summary>
/// Durable home of wrapped data keys. Implementations: <see cref="InMemoryDataKeyStore"/> and
/// <c>FieldCrypto.Dapper.SqlDataKeyStore</c> (PostgreSQL). The store holds only wrapped keys, so reading it
/// without the KMS reveals nothing; writing to it can at worst make data unreadable (denial of service), which
/// the wrap's associated data turns into a detected error rather than a wrong plaintext.
/// </summary>
public interface IDataKeyStore
{
    /// <summary>Inserts the record. Returns false when a record with the same id already exists.</summary>
    Task<bool> TryInsertAsync(DataKeyRecord record, CancellationToken cancellationToken = default);

    bool TryInsert(DataKeyRecord record);

    Task<DataKeyRecord?> FindAsync(Guid id, CancellationToken cancellationToken = default);

    DataKeyRecord? Find(Guid id);

    Task<IReadOnlyList<DataKeyRecord>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces the wrapping of one record if it is still wrapped by <paramref name="expectedKekId"/> at
    /// <paramref name="expectedKekVersion"/> (optimistic concurrency: two rewrap jobs never overwrite each other).
    /// </summary>
    Task<bool> TryUpdateWrappingAsync(
        Guid id,
        string expectedKekId,
        string expectedKekVersion,
        string newKekId,
        string newKekVersion,
        byte[] newWrappedKey,
        CancellationToken cancellationToken = default);

    Task RetireAsync(Guid id, DateTimeOffset retiredAt, CancellationToken cancellationToken = default);
}
