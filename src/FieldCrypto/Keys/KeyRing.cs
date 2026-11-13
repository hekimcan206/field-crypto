using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using FieldCrypto.Kms;

namespace FieldCrypto.Keys;

public sealed class KeyRingOptions
{
    /// <summary>
    /// Encryptions per data key before a new one is generated. Field ciphertexts use random 96-bit GCM nonces, and
    /// NIST SP 800-38D caps random-nonce use at 2^32 messages per key; the default stays more than three orders of
    /// magnitude below that, so the nonce-collision probability stays negligible (about 2^-58 per key).
    /// </summary>
    public long MaxMessagesPerDataKey { get; set; } = 1_000_000;

    /// <summary>Age after which the active data key is replaced even if the message budget is not used up.</summary>
    public TimeSpan MaxDataKeyAge { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// KEKs that wrapped older data keys (for example the local development KEK before moving to OCI Vault). They are
    /// used only to unwrap; <see cref="KeyRing.RewrapAsync"/> moves their data keys to the current KEK.
    /// </summary>
    public IList<IKeyEncryptionService> PreviousKeyEncryptionServices { get; } = [];
}

public readonly record struct KeyRingStatistics(long KmsWraps, long KmsUnwraps, long CacheHits, long CacheMisses, long DataKeysCreated);

/// <param name="Examined">Data key records looked at.</param>
/// <param name="Rewrapped">Records now wrapped by the current KEK version.</param>
/// <param name="AlreadyCurrent">Records that needed nothing.</param>
/// <param name="Conflicts">Records another rewrap changed first (left to it).</param>
public readonly record struct RewrapResult(int Examined, int Rewrapped, int AlreadyCurrent, int Conflicts);

/// <summary>
/// Owns the data keys: generates and wraps them, caches unwrapped keys, enforces the per-key message budget, and
/// rewraps them when the KEK rotates. One instance per process (register it as a singleton).
/// </summary>
/// <remarks>
/// The cache is the reason envelope encryption is affordable: without it every field write would be a KMS round
/// trip (see docs/benchmarks.md). The cache holds plaintext data keys in process memory for the process lifetime;
/// that is the trade-off every envelope-encryption client makes, documented in docs/threat-model.md.
/// </remarks>
public sealed class KeyRing : IDisposable
{
    /// <summary>
    /// Fixed id of the blind index root key. A fixed id plus insert-if-absent makes concurrently starting processes
    /// converge on one root key; random ids would let two processes compute incompatible indexes.
    /// </summary>
    public static readonly Guid BlindIndexRootKeyId = new("6d1f0a52-2c4e-4b3e-9f6a-0b8c1d2e3f40");

    private const int KeySize = 32;
    private readonly IKeyEncryptionService _kek;
    private readonly IDataKeyStore _store;
    private readonly KeyRingOptions _options;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<Guid, byte[]> _cache = new();
    private readonly SemaphoreSlim _rolloverGate = new(1, 1);
    private readonly SemaphoreSlim _loadGate = new(1, 1);
    private ActiveDataKey? _active;
    private byte[]? _blindIndexRootKey;
    private long _wraps;
    private long _unwraps;
    private long _hits;
    private long _misses;
    private long _created;

    public KeyRing(IKeyEncryptionService keyEncryptionService, IDataKeyStore store, KeyRingOptions? options = null, TimeProvider? timeProvider = null)
    {
        _kek = keyEncryptionService ?? throw new ArgumentNullException(nameof(keyEncryptionService));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? new KeyRingOptions();
        _time = timeProvider ?? TimeProvider.System;
        if (_options.MaxMessagesPerDataKey < 1 || _options.MaxMessagesPerDataKey > (1L << 32))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxMessagesPerDataKey must be between 1 and 2^32.");
        }
    }

    public IKeyEncryptionService KeyEncryptionService => _kek;

    public IDataKeyStore Store => _store;

    public Guid? ActiveDataKeyId => Volatile.Read(ref _active)?.Id;

    public KeyRingStatistics Statistics => new(
        Interlocked.Read(ref _wraps),
        Interlocked.Read(ref _unwraps),
        Interlocked.Read(ref _hits),
        Interlocked.Read(ref _misses),
        Interlocked.Read(ref _created));

    /// <summary>Loads (or creates) the blind index root key and the first data key, so the first request pays nothing.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await GetBlindIndexRootKeyCore(useAsync: true, cancellationToken);
        if (Volatile.Read(ref _active) is null)
        {
            await RolloverCore(stale: null, useAsync: true, cancellationToken);
        }
    }

    /// <summary>Stops the active data key from encrypting. Rows that use it are found by the re-encryption job.</summary>
    public async Task<Guid?> RetireActiveDataKeyAsync(CancellationToken cancellationToken = default)
    {
        var active = Volatile.Read(ref _active);
        if (active is null)
        {
            return null;
        }

        await RetireDataKeyAsync(active.Id, cancellationToken);
        return active.Id;
    }

    public async Task RetireDataKeyAsync(Guid dataKeyId, CancellationToken cancellationToken = default)
    {
        await _store.RetireAsync(dataKeyId, _time.GetUtcNow(), cancellationToken);
        var active = Volatile.Read(ref _active);
        if (active?.Id == dataKeyId)
        {
            Interlocked.CompareExchange(ref _active, null, active);
        }
    }

    /// <summary>
    /// Rewraps every data key that is not wrapped by the current KEK version. This is the whole cost of a KEK
    /// rotation: one unwrap and one wrap per data key, and not a single data row is read or written.
    /// </summary>
    public async Task<RewrapResult> RewrapAsync(CancellationToken cancellationToken = default)
    {
        using var activity = FieldCryptoTelemetry.ActivitySource.StartActivity("fieldcrypto.rewrap");
        var current = await _kek.GetCurrentKeyVersionAsync(cancellationToken);
        int examined = 0, rewrapped = 0, upToDate = 0, conflicts = 0;
        foreach (var record in await _store.ListAsync(cancellationToken))
        {
            examined++;
            if (record.KekId == _kek.KeyId && record.KekVersion == current)
            {
                upToDate++;
                continue;
            }

            var context = new KeyWrapContext(record.Id, record.PurposeName);
            var plaintext = await UnwrapWith(ResolveKek(record.KekId), record.WrappedKey, context, useAsync: true, cancellationToken);
            try
            {
                var wrapped = await WrapWith(plaintext, context, useAsync: true, cancellationToken);
                var updated = await _store.TryUpdateWrappingAsync(
                    record.Id, record.KekId, record.KekVersion, _kek.KeyId, wrapped.KeyVersion, wrapped.Ciphertext, cancellationToken);
                if (updated)
                {
                    rewrapped++;
                }
                else
                {
                    conflicts++;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        activity?.SetTag("fieldcrypto.rewrapped", rewrapped);
        return new RewrapResult(examined, rewrapped, upToDate, conflicts);
    }

    internal DataKeyLease Acquire() => RunSync(AcquireCore(useAsync: false, CancellationToken.None));

    internal ValueTask<DataKeyLease> AcquireAsync(CancellationToken cancellationToken) => AcquireCore(useAsync: true, cancellationToken);

    internal byte[] GetDataKey(Guid id) =>
        TryGetCached(id, out var key) ? key : RunSync(LoadDataKeyCore(id, useAsync: false, CancellationToken.None));

    internal ValueTask<byte[]> GetDataKeyAsync(Guid id, CancellationToken cancellationToken) =>
        TryGetCached(id, out var key) ? ValueTask.FromResult(key) : LoadDataKeyCore(id, useAsync: true, cancellationToken);

    internal byte[] GetBlindIndexRootKey() =>
        Volatile.Read(ref _blindIndexRootKey) ?? RunSync(GetBlindIndexRootKeyCore(useAsync: false, CancellationToken.None));

    public void Dispose()
    {
        foreach (var key in _cache.Values)
        {
            CryptographicOperations.ZeroMemory(key);
        }

        _cache.Clear();
        if (_blindIndexRootKey is not null)
        {
            CryptographicOperations.ZeroMemory(_blindIndexRootKey);
        }

        _rolloverGate.Dispose();
        _loadGate.Dispose();
    }

    // The *Core methods follow the "bool async" pattern (as in Npgsql and System.IO): with useAsync = false every
    // awaited operation completes synchronously, so the synchronous API is truly synchronous, not sync-over-async.
    private async ValueTask<DataKeyLease> AcquireCore(bool useAsync, CancellationToken cancellationToken)
    {
        while (true)
        {
            var active = Volatile.Read(ref _active);
            if (active is not null && _time.GetUtcNow() - active.CreatedAt < _options.MaxDataKeyAge)
            {
                // Increment first, check after: the counter may overshoot under contention, but no more than
                // MaxMessagesPerDataKey callers ever receive this key.
                if (Interlocked.Increment(ref active.Used) <= _options.MaxMessagesPerDataKey)
                {
                    return new DataKeyLease(active.Id, active.Key);
                }
            }

            await RolloverCore(active, useAsync, cancellationToken);
        }
    }

    private async ValueTask RolloverCore(ActiveDataKey? stale, bool useAsync, CancellationToken cancellationToken)
    {
        await Enter(_rolloverGate, useAsync, cancellationToken);
        try
        {
            if (!ReferenceEquals(Volatile.Read(ref _active), stale))
            {
                return;
            }

            var now = _time.GetUtcNow();
            var id = Guid.CreateVersion7(now);
            var key = RandomNumberGenerator.GetBytes(KeySize);
            var wrapped = await WrapWith(key, new KeyWrapContext(id, "data"), useAsync, cancellationToken);
            var record = new DataKeyRecord(id, DataKeyPurpose.Data, _kek.KeyId, wrapped.KeyVersion, wrapped.Ciphertext, now);
            // Persist before first use: a ciphertext must never reference a data key the store does not have.
            var inserted = useAsync ? await _store.TryInsertAsync(record, cancellationToken) : _store.TryInsert(record);
            if (!inserted)
            {
                throw new InvalidOperationException($"Data key id {id} already exists in the key store.");
            }

            _cache[id] = key;
            Interlocked.Increment(ref _created);
            FieldCryptoTelemetry.DataKeysCreated.Add(1);
            Volatile.Write(ref _active, new ActiveDataKey(id, key, now));
        }
        finally
        {
            _rolloverGate.Release();
        }
    }

    private bool TryGetCached(Guid id, out byte[] key)
    {
        if (_cache.TryGetValue(id, out key!))
        {
            Interlocked.Increment(ref _hits);
            FieldCryptoTelemetry.DataKeyLookups.Add(1, new KeyValuePair<string, object?>("result", "hit"));
            return true;
        }

        return false;
    }

    private async ValueTask<byte[]> LoadDataKeyCore(Guid id, bool useAsync, CancellationToken cancellationToken)
    {
        // Misses are rare (one per data key per process), so serialising them is cheap and stops a cold-start
        // stampede from sending one KMS call per concurrent request for the same key.
        await Enter(_loadGate, useAsync, cancellationToken);
        try
        {
            if (_cache.TryGetValue(id, out var cached))
            {
                return cached;
            }

            Interlocked.Increment(ref _misses);
            FieldCryptoTelemetry.DataKeyLookups.Add(1, new KeyValuePair<string, object?>("result", "miss"));
            var record = (useAsync ? await _store.FindAsync(id, cancellationToken) : _store.Find(id))
                ?? throw new FieldDecryptionException(FieldDecryptionFailure.UnknownDataKey, $"Data key {id} is not in the key store.");
            if (record.Purpose != DataKeyPurpose.Data)
            {
                throw new FieldDecryptionException(FieldDecryptionFailure.Malformed, $"Key {id} is not a data encryption key.");
            }

            byte[] key;
            try
            {
                key = await UnwrapWith(ResolveKek(record.KekId), record.WrappedKey, new KeyWrapContext(id, record.PurposeName), useAsync, cancellationToken);
            }
            catch (CryptographicException ex)
            {
                throw new FieldDecryptionException(FieldDecryptionFailure.DataKeyUnwrapFailed, $"Data key {id} could not be unwrapped by the KMS.", ex);
            }

            _cache[id] = key;
            return key;
        }
        finally
        {
            _loadGate.Release();
        }
    }

    private async ValueTask<byte[]> GetBlindIndexRootKeyCore(bool useAsync, CancellationToken cancellationToken)
    {
        await Enter(_loadGate, useAsync, cancellationToken);
        try
        {
            if (_blindIndexRootKey is { } loaded)
            {
                return loaded;
            }

            var id = BlindIndexRootKeyId;
            var context = new KeyWrapContext(id, "blind-index");
            var record = useAsync ? await _store.FindAsync(id, cancellationToken) : _store.Find(id);
            if (record is null)
            {
                var fresh = RandomNumberGenerator.GetBytes(KeySize);
                var wrapped = await WrapWith(fresh, context, useAsync, cancellationToken);
                var candidate = new DataKeyRecord(id, DataKeyPurpose.BlindIndex, _kek.KeyId, wrapped.KeyVersion, wrapped.Ciphertext, _time.GetUtcNow());
                var inserted = useAsync ? await _store.TryInsertAsync(candidate, cancellationToken) : _store.TryInsert(candidate);
                if (inserted)
                {
                    Volatile.Write(ref _blindIndexRootKey, fresh);
                    return fresh;
                }

                // Another process won the race: use its key, or the indexes would disagree.
                record = (useAsync ? await _store.FindAsync(id, cancellationToken) : _store.Find(id))
                    ?? throw new InvalidOperationException("Blind index root key vanished during initialisation.");
            }

            var key = await UnwrapWith(ResolveKek(record.KekId), record.WrappedKey, context, useAsync, cancellationToken);
            Volatile.Write(ref _blindIndexRootKey, key);
            return key;
        }
        finally
        {
            _loadGate.Release();
        }
    }

    private async ValueTask<WrappedDataKey> WrapWith(byte[] key, KeyWrapContext context, bool useAsync, CancellationToken cancellationToken)
    {
        using var activity = StartKmsActivity("wrap", _kek.KeyId);
        Interlocked.Increment(ref _wraps);
        FieldCryptoTelemetry.KmsCalls.Add(1, new KeyValuePair<string, object?>("operation", "wrap"));
        return useAsync ? await _kek.WrapAsync(key, context, cancellationToken) : _kek.Wrap(key, context);
    }

    private async ValueTask<byte[]> UnwrapWith(IKeyEncryptionService kek, byte[] wrapped, KeyWrapContext context, bool useAsync, CancellationToken cancellationToken)
    {
        using var activity = StartKmsActivity("unwrap", kek.KeyId);
        Interlocked.Increment(ref _unwraps);
        FieldCryptoTelemetry.KmsCalls.Add(1, new KeyValuePair<string, object?>("operation", "unwrap"));
        return useAsync ? await kek.UnwrapAsync(wrapped, context, cancellationToken) : kek.Unwrap(wrapped, context);
    }

    private IKeyEncryptionService ResolveKek(string kekId)
    {
        if (kekId == _kek.KeyId)
        {
            return _kek;
        }

        return _options.PreviousKeyEncryptionServices.FirstOrDefault(k => k.KeyId == kekId)
            ?? throw new FieldDecryptionException(FieldDecryptionFailure.DataKeyUnwrapFailed, $"No KMS is configured for KEK '{kekId}'.");
    }

    private static Activity? StartKmsActivity(string operation, string kekId)
    {
        var activity = FieldCryptoTelemetry.ActivitySource.StartActivity("fieldcrypto.kms." + operation, ActivityKind.Client);
        activity?.SetTag("fieldcrypto.kek.id", kekId);
        return activity;
    }

    private static ValueTask Enter(SemaphoreSlim gate, bool useAsync, CancellationToken cancellationToken)
    {
        if (useAsync)
        {
            return new ValueTask(gate.WaitAsync(cancellationToken));
        }

        gate.Wait(cancellationToken);
        return ValueTask.CompletedTask;
    }

    private static T RunSync<T>(ValueTask<T> task)
    {
        Debug.Assert(task.IsCompleted, "A synchronous code path awaited something asynchronous.");
        return task.GetAwaiter().GetResult();
    }

    private sealed class ActiveDataKey(Guid id, byte[] key, DateTimeOffset createdAt)
    {
        public long Used;

        public Guid Id { get; } = id;

        public byte[] Key { get; } = key;

        public DateTimeOffset CreatedAt { get; } = createdAt;
    }
}

internal readonly record struct DataKeyLease(Guid Id, byte[] Key);
