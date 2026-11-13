using System.Collections.Concurrent;
using FieldCrypto.Keys;
using FieldCrypto.Kms;
using FieldCrypto.UnitTests.Support;
using Microsoft.Extensions.Time.Testing;

namespace FieldCrypto.UnitTests;

public sealed class KeyRingTests
{
    private static readonly EncryptionContext Email = new("patients", "email");

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void Ten_thousand_encryptions_cost_one_wrap()
    {
        using var ring = new TestRing();

        for (var i = 0; i < 10_000; i++)
        {
            ring.Encryptor.Encrypt("ayse@example.test", Email);
        }

        ring.Ring.Statistics.KmsWraps.Should().Be(1);
        ring.Store.Count.Should().Be(1);
    }

    [Fact]
    public void A_new_data_key_starts_when_the_message_budget_is_spent()
    {
        using var ring = new TestRing(new KeyRingOptions { MaxMessagesPerDataKey = 100 });

        var keyIds = Enumerable.Range(0, 250).Select(_ => DataKeyOf(ring.Encryptor.Encrypt("x", Email))).ToList();

        keyIds.Distinct().Should().HaveCount(3);
        keyIds.GroupBy(id => id).Select(g => g.Count()).Should().Equal(100, 100, 50);
    }

    [Fact]
    public void A_new_data_key_starts_when_the_active_one_is_too_old()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-11-13T09:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        using var ring = new TestRing(new KeyRingOptions { MaxDataKeyAge = TimeSpan.FromHours(1) }, time);

        var first = DataKeyOf(ring.Encryptor.Encrypt("x", Email));
        time.Advance(TimeSpan.FromMinutes(59));
        var stillFirst = DataKeyOf(ring.Encryptor.Encrypt("x", Email));
        time.Advance(TimeSpan.FromMinutes(1));
        var second = DataKeyOf(ring.Encryptor.Encrypt("x", Email));

        stillFirst.Should().Be(first);
        second.Should().NotBe(first);
    }

    [Fact]
    public async Task Concurrent_writers_never_push_a_data_key_past_its_budget()
    {
        const int budget = 997;
        using var ring = new TestRing(new KeyRingOptions { MaxMessagesPerDataKey = budget });
        var perKey = new ConcurrentDictionary<Guid, int>();

        await Parallel.ForAsync(0, 50_000, new ParallelOptions { MaxDegreeOfParallelism = 16, CancellationToken = Ct }, async (i, token) =>
        {
            var ciphertext = i % 2 == 0
                ? ring.Encryptor.Encrypt("x", Email)
                : await ring.Encryptor.EncryptAsync("x", Email, token);
            perKey.AddOrUpdate(DataKeyOf(ciphertext), 1, (_, n) => n + 1);
        });

        perKey.Values.Should().OnlyContain(n => n <= budget);
        perKey.Values.Sum().Should().Be(50_000);
        ring.Ring.Statistics.DataKeysCreated.Should().Be(perKey.Count);
    }

    [Fact]
    public async Task Initialize_creates_the_first_data_key_without_spending_budget()
    {
        using var ring = new TestRing(new KeyRingOptions { MaxMessagesPerDataKey = 2 });

        await ring.Ring.InitializeAsync(Ct);
        var keys = Enumerable.Range(0, 2).Select(_ => DataKeyOf(ring.Encryptor.Encrypt("x", Email))).ToList();

        keys.Should().AllBeEquivalentTo(ring.Ring.ActiveDataKeyId!.Value);
        ring.Store.Count.Should().Be(2, "the data key and the blind index root key");
    }

    [Fact]
    public async Task Retiring_the_active_key_moves_new_writes_to_a_fresh_one_and_old_values_still_decrypt()
    {
        using var ring = new TestRing();
        var before = ring.Encryptor.Encrypt("old", Email);

        var retired = await ring.Ring.RetireActiveDataKeyAsync(Ct);
        var after = ring.Encryptor.Encrypt("new", Email);

        DataKeyOf(after).Should().NotBe(retired!.Value);
        ring.Store.Find(retired.Value)!.RetiredAt.Should().NotBeNull();
        ring.Encryptor.Decrypt(before, Email).Should().Be("old");
    }

    [Fact]
    public async Task Kek_rotation_rewraps_every_data_key_and_nothing_else()
    {
        using var ring = new TestRing(new KeyRingOptions { MaxMessagesPerDataKey = 10 });
        var values = Enumerable.Range(0, 95).Select(i => (Plain: $"v{i}", Cipher: ring.Encryptor.Encrypt($"v{i}", Email))).ToList();
        await ring.Ring.InitializeAsync(Ct);
        var dataKeys = ring.Store.Count;

        var newVersion = ring.Kek.Rotate();
        var result = await ring.Ring.RewrapAsync(Ct);

        result.Should().Be(new RewrapResult(dataKeys, dataKeys, 0, 0));
        (await ring.Store.ListAsync(Ct)).Should().OnlyContain(r => r.KekVersion == newVersion);
        using var restarted = ring.Restart();
        values.Should().OnlyContain(v => restarted.Encryptor.Decrypt(v.Cipher, Email) == v.Plain);
    }

    [Fact]
    public async Task Rewrap_is_idempotent()
    {
        using var ring = new TestRing();
        ring.Encryptor.Encrypt("x", Email);
        ring.Kek.Rotate();

        await ring.Ring.RewrapAsync(Ct);
        var second = await ring.Ring.RewrapAsync(Ct);

        second.Rewrapped.Should().Be(0);
        second.AlreadyCurrent.Should().Be(second.Examined);
    }

    [Fact]
    public async Task Rewrap_migrates_data_keys_from_a_previous_kms()
    {
        var oldKms = LocalKeyEncryptionService.CreateEphemeral("dev-kek");
        var store = new InMemoryDataKeyStore();
        byte[] ciphertext;
        using (var before = new TestRing(kek: oldKms, store: store))
        {
            ciphertext = before.Encryptor.Encrypt("ayse@example.test", Email);
        }

        var newKms = LocalKeyEncryptionService.CreateEphemeral("prod-kek");
        var options = new KeyRingOptions();
        options.PreviousKeyEncryptionServices.Add(oldKms);
        using var after = new TestRing(options, kek: newKms, store: store);

        after.Encryptor.Decrypt(ciphertext, Email).Should().Be("ayse@example.test", "the old KMS still unwraps before migration");
        var result = await after.Ring.RewrapAsync(Ct);

        result.Rewrapped.Should().Be(1);
        using var withoutOld = new TestRing(kek: newKms, store: store);
        withoutOld.Encryptor.Decrypt(ciphertext, Email).Should().Be("ayse@example.test");
    }

    [Fact]
    public async Task Rewrap_leaves_a_record_another_rewrap_changed_first()
    {
        using var ring = new TestRing();
        ring.Encryptor.Encrypt("x", Email);
        var record = (await ring.Store.ListAsync(Ct)).Single();

        (await ring.Store.TryUpdateWrappingAsync(record.Id, record.KekId, "999", "k", "2", [1], Ct)).Should().BeFalse();
        (await ring.Store.TryUpdateWrappingAsync(record.Id, record.KekId, record.KekVersion, record.KekId, record.KekVersion, record.WrappedKey, Ct)).Should().BeTrue();
    }

    [Fact]
    public void A_wrapped_key_copied_onto_another_key_id_does_not_unwrap()
    {
        using var ring = new TestRing(new KeyRingOptions { MaxMessagesPerDataKey = 1 });
        var first = ring.Encryptor.Encrypt("a", Email);
        var second = ring.Encryptor.Encrypt("b", Email);
        var a = ring.Store.Find(DataKeyOf(first))!;
        var b = ring.Store.Find(DataKeyOf(second))!;
        var tampered = new InMemoryDataKeyStore();
        tampered.TryInsert(a with { WrappedKey = b.WrappedKey });

        using var victim = new TestRing(kek: ring.Kek, store: tampered);
        var act = () => victim.Encryptor.Decrypt(first, Email);

        act.Should().Throw<FieldDecryptionException>().Which.Failure.Should().Be(FieldDecryptionFailure.DataKeyUnwrapFailed);
    }

    [Fact]
    public void Concurrent_first_use_on_two_processes_converges_on_one_blind_index_key()
    {
        var kek = LocalKeyEncryptionService.CreateEphemeral();
        var store = new InMemoryDataKeyStore();
        var definition = new BlindIndexing.BlindIndexDefinition("patients", "email", 32);

        var values = new long[8];
        Parallel.For(0, values.Length, i =>
        {
            using var ring = new TestRing(kek: kek, store: store);
            values[i] = ring.Indexer.Compute("ayse@example.test", definition);
        });

        values.Distinct().Should().ContainSingle();
        store.Find(KeyRing.BlindIndexRootKeyId)!.Purpose.Should().Be(DataKeyPurpose.BlindIndex);
    }

    [Fact]
    public void A_missing_previous_kms_is_a_clear_error()
    {
        var store = new InMemoryDataKeyStore();
        byte[] ciphertext;
        using (var before = new TestRing(kek: LocalKeyEncryptionService.CreateEphemeral("gone"), store: store))
        {
            ciphertext = before.Encryptor.Encrypt("x", Email);
        }

        using var after = new TestRing(store: store);
        var act = () => after.Encryptor.Decrypt(ciphertext, Email);

        act.Should().Throw<FieldDecryptionException>().WithMessage("*No KMS is configured for KEK 'gone'*");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4_294_967_297)]
    public void Message_budget_must_stay_within_the_gcm_random_nonce_bound(long budget)
    {
        var act = () => new KeyRing(LocalKeyEncryptionService.CreateEphemeral(), new InMemoryDataKeyStore(), new KeyRingOptions { MaxMessagesPerDataKey = budget });

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    private static Guid DataKeyOf(byte[] ciphertext)
    {
        CiphertextLayout.TryReadDataKeyId(ciphertext, out var id).Should().BeTrue();
        return id;
    }
}
