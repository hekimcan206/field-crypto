using FieldCrypto.UnitTests.Support;

namespace FieldCrypto.UnitTests;

public sealed class EnvelopeTests : IDisposable
{
    private static readonly EncryptionContext NationalId = new("patients", "national_id");
    private readonly TestRing _ring = new();

    public void Dispose() => _ring.Dispose();

    [Theory]
    [InlineData("")]
    [InlineData("10000000146")]
    [InlineData("Şükrü Çağlayan Öztürk")]
    [InlineData("emoji 🙂 and \u0000 nul")]
    public void Round_trips_any_text(string plaintext)
    {
        var ciphertext = _ring.Encryptor.Encrypt(plaintext, NationalId);

        _ring.Encryptor.Decrypt(ciphertext, NationalId).Should().Be(plaintext);
    }

    [Fact]
    public async Task Async_and_sync_paths_are_interchangeable()
    {
        var ciphertext = await _ring.Encryptor.EncryptAsync("10000000146", NationalId, TestContext.Current.CancellationToken);

        _ring.Encryptor.Decrypt(ciphertext, NationalId).Should().Be("10000000146");
        (await _ring.Encryptor.DecryptAsync(_ring.Encryptor.Encrypt("x", NationalId), NationalId, TestContext.Current.CancellationToken)).Should().Be("x");
    }

    [Fact]
    public void Ciphertext_is_plaintext_length_plus_45_bytes()
    {
        _ring.Encryptor.Encrypt("10000000146", NationalId).Should().HaveCount(11 + CiphertextLayout.Overhead);
        CiphertextLayout.Overhead.Should().Be(45);
    }

    [Fact]
    public void Same_plaintext_encrypts_differently_every_time()
    {
        var ciphertexts = Enumerable.Range(0, 10_000).Select(_ => Convert.ToHexString(_ring.Encryptor.Encrypt("same", NationalId))).ToList();

        ciphertexts.Distinct().Should().HaveCount(10_000);
        ciphertexts.Select(c => c.Substring(34, 24)).Distinct().Should().HaveCount(10_000, "every nonce is fresh");
    }

    [Fact]
    public void Header_names_the_data_key_without_decrypting()
    {
        var ciphertext = _ring.Encryptor.Encrypt("x", NationalId);

        CiphertextLayout.TryReadDataKeyId(ciphertext, out var id).Should().BeTrue();
        id.Should().Be(_ring.Ring.ActiveDataKeyId!.Value);
        ciphertext[0].Should().Be(CiphertextLayout.Version1);
    }

    public static TheoryData<string, EncryptionContext> WrongPlaces => new()
    {
        { "other column", new EncryptionContext("patients", "phone") },
        { "other table", new EncryptionContext("staff", "national_id") },
        { "row-bound read of a column-bound value", new EncryptionContext("patients", "national_id", "42") },
    };

    [Theory]
    [MemberData(nameof(WrongPlaces))]
    public void Ciphertext_moved_elsewhere_does_not_decrypt(string because, EncryptionContext wrongPlace)
    {
        var ciphertext = _ring.Encryptor.Encrypt("10000000146", NationalId);

        var act = () => _ring.Encryptor.Decrypt(ciphertext, wrongPlace);

        act.Should().Throw<FieldDecryptionException>(because).Which.Failure.Should().Be(FieldDecryptionFailure.AuthenticationFailed);
    }

    [Fact]
    public void Row_bound_ciphertext_does_not_decrypt_in_another_row()
    {
        var row42 = NationalId.WithRow("42");
        var ciphertext = _ring.Encryptor.Encrypt("10000000146", row42);

        _ring.Encryptor.Decrypt(ciphertext, row42).Should().Be("10000000146");
        var act = () => _ring.Encryptor.Decrypt(ciphertext, NationalId.WithRow("43"));
        act.Should().Throw<FieldDecryptionException>().Which.Failure.Should().Be(FieldDecryptionFailure.AuthenticationFailed);
    }

    [Fact]
    public void Truncated_ciphertext_is_malformed()
    {
        var act = () => _ring.Encryptor.Decrypt(new byte[CiphertextLayout.Overhead - 1], NationalId);

        act.Should().Throw<FieldDecryptionException>().Which.Failure.Should().Be(FieldDecryptionFailure.Malformed);
    }

    [Fact]
    public void Unknown_format_version_is_reported_as_such()
    {
        var ciphertext = _ring.Encryptor.Encrypt("x", NationalId);
        ciphertext[0] = 0x02;

        var act = () => _ring.Encryptor.Decrypt(ciphertext, NationalId);

        act.Should().Throw<FieldDecryptionException>().Which.Failure.Should().Be(FieldDecryptionFailure.UnsupportedVersion);
    }

    [Fact]
    public void Ciphertext_from_another_key_store_names_an_unknown_data_key()
    {
        using var other = new TestRing();
        var ciphertext = other.Encryptor.Encrypt("x", NationalId);

        var act = () => _ring.Encryptor.Decrypt(ciphertext, NationalId);

        act.Should().Throw<FieldDecryptionException>().Which.Failure.Should().Be(FieldDecryptionFailure.UnknownDataKey);
    }

    [Fact]
    public async Task Repointing_the_header_at_another_data_key_fails_authentication()
    {
        var first = _ring.Encryptor.Encrypt("x", NationalId);
        await _ring.Ring.RetireActiveDataKeyAsync(TestContext.Current.CancellationToken);
        var second = _ring.Encryptor.Encrypt("y", NationalId);
        first.AsSpan(1, 16).SequenceEqual(second.AsSpan(1, 16)).Should().BeFalse();

        second.AsSpan(1, 16).CopyTo(first.AsSpan(1, 16));
        var act = () => _ring.Encryptor.Decrypt(first, NationalId);

        act.Should().Throw<FieldDecryptionException>().Which.Failure.Should().Be(FieldDecryptionFailure.AuthenticationFailed);
    }

    [Fact]
    public void Error_messages_never_contain_the_plaintext()
    {
        var ciphertext = _ring.Encryptor.Encrypt("10000000146", NationalId);
        ciphertext[^1] ^= 1;

        var act = () => _ring.Encryptor.Decrypt(ciphertext, NationalId);

        act.Should().Throw<FieldDecryptionException>().Which.ToString().Should().NotContain("10000000146");
    }

    [Fact]
    public void A_restarted_process_decrypts_with_one_unwrap()
    {
        var ciphertexts = Enumerable.Range(0, 100).Select(i => _ring.Encryptor.Encrypt($"value {i}", NationalId)).ToList();
        using var restarted = _ring.Restart();

        ciphertexts.Select(c => restarted.Encryptor.Decrypt(c, NationalId)).Should().Equal(Enumerable.Range(0, 100).Select(i => $"value {i}"));
        restarted.Ring.Statistics.KmsUnwraps.Should().Be(1);
        restarted.Ring.Statistics.CacheMisses.Should().Be(1);
        restarted.Ring.Statistics.CacheHits.Should().Be(99);
    }

    [Fact]
    public void Context_rejects_blank_names()
    {
        var blankTable = () => new EncryptionContext(" ", "c");
        var emptyRow = () => new EncryptionContext("t", "c", string.Empty);

        blankTable.Should().Throw<ArgumentException>();
        emptyRow.Should().Throw<ArgumentException>();
    }
}
