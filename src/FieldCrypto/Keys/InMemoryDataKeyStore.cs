using System.Collections.Concurrent;

namespace FieldCrypto.Keys;

/// <summary>Process-local store for tests, benchmarks and single-process tools. Keys vanish with the process.</summary>
public sealed class InMemoryDataKeyStore : IDataKeyStore
{
    private readonly ConcurrentDictionary<Guid, DataKeyRecord> _records = new();

    public int Count => _records.Count;

    public Task<bool> TryInsertAsync(DataKeyRecord record, CancellationToken cancellationToken = default) =>
        Task.FromResult(TryInsert(record));

    public bool TryInsert(DataKeyRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return _records.TryAdd(record.Id, record);
    }

    public Task<DataKeyRecord?> FindAsync(Guid id, CancellationToken cancellationToken = default) => Task.FromResult(Find(id));

    public DataKeyRecord? Find(Guid id) => _records.GetValueOrDefault(id);

    public Task<IReadOnlyList<DataKeyRecord>> ListAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<DataKeyRecord>>([.. _records.Values.OrderBy(r => r.CreatedAt).ThenBy(r => r.Id)]);

    public Task<bool> TryUpdateWrappingAsync(
        Guid id,
        string expectedKekId,
        string expectedKekVersion,
        string newKekId,
        string newKekVersion,
        byte[] newWrappedKey,
        CancellationToken cancellationToken = default)
    {
        if (!_records.TryGetValue(id, out var current)
            || current.KekId != expectedKekId
            || current.KekVersion != expectedKekVersion)
        {
            return Task.FromResult(false);
        }

        var updated = current with { KekId = newKekId, KekVersion = newKekVersion, WrappedKey = newWrappedKey };
        return Task.FromResult(_records.TryUpdate(id, updated, current));
    }

    public Task RetireAsync(Guid id, DateTimeOffset retiredAt, CancellationToken cancellationToken = default)
    {
        while (_records.TryGetValue(id, out var current) && current.RetiredAt is null)
        {
            if (_records.TryUpdate(id, current with { RetiredAt = retiredAt }, current))
            {
                break;
            }
        }

        return Task.CompletedTask;
    }
}
