using FieldCrypto.BlindIndexing;
using FieldCrypto.Keys;
using FieldCrypto.Kms;

namespace FieldCrypto.UnitTests.Support;

/// <summary>A key ring over a local KEK and an in-memory store, with the pieces exposed for assertions.</summary>
internal sealed class TestRing : IDisposable
{
    public TestRing(KeyRingOptions? options = null, TimeProvider? time = null, LocalKeyEncryptionService? kek = null, InMemoryDataKeyStore? store = null)
    {
        Kek = kek ?? LocalKeyEncryptionService.CreateEphemeral();
        Store = store ?? new InMemoryDataKeyStore();
        Ring = new KeyRing(Kek, Store, options, time);
        Encryptor = new FieldEncryptor(Ring);
        Indexer = new BlindIndexer(Ring);
    }

    public LocalKeyEncryptionService Kek { get; }

    public InMemoryDataKeyStore Store { get; }

    public KeyRing Ring { get; }

    public FieldEncryptor Encryptor { get; }

    public BlindIndexer Indexer { get; }

    /// <summary>A second process: same KMS and key store, empty caches.</summary>
    public TestRing Restart(KeyRingOptions? options = null) => new(options, kek: Kek, store: Store);

    public void Dispose() => Ring.Dispose();
}
