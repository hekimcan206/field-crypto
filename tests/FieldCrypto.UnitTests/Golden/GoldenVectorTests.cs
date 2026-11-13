using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FieldCrypto.BlindIndexing;

namespace FieldCrypto.UnitTests.Golden;

/// <summary>
/// Fixed-input vectors for the ciphertext format and the blind index. They pin the on-disk format: a change that makes
/// existing rows undecryptable or existing indexes unsearchable fails here first. Each ciphertext vector is also
/// re-derived from the written specification (docs/ciphertext-format.md) with raw AES-GCM, independent of the library's
/// encoder. Regenerate only for a deliberate format change: UPDATE_GOLDEN=1 dotnet test.
/// </summary>
public sealed class GoldenVectorTests
{
    private static readonly string VectorFile = Path.Combine(AppContext.BaseDirectory, "Golden", "vectors.json");
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private static readonly byte[] Key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly Guid DataKeyId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8057");

    private static readonly (string Name, string Plaintext, string Table, string Column, string? Row, string Nonce)[] CipherInputs =
    [
        ("column-bound national id", "10000000146", "patients", "national_id", null, "000000000000000000000001"),
        ("row-bound national id", "10000000146", "patients", "national_id", "42", "000000000000000000000002"),
        ("empty plaintext", "", "staff", "email", null, "ffffffffffffffffffffffff"),
        ("turkish text, non-ascii row key", "Şükrü Çağlayan", "patients", "full_name", "ş-1", "a1a2a3a4a5a6a7a8a9aaabac"),
    ];

    private static readonly (string Name, string Input, string Table, string Column, int Bits, string Normalizer)[] IndexInputs =
    [
        ("national id, 16 bits", "100 000 001 46", "patients", "national_id", 16, "digits"),
        ("national id, 32 bits", "10000000146", "patients", "national_id", 32, "digits"),
        ("surname, turkish fold", "IŞIK", "patients", "surname", 20, "turkish"),
        ("email", " Ayse.Yilmaz@Example.TEST", "patients", "email", 24, "email"),
    ];

    [Fact]
    public void Vectors_match_the_committed_file()
    {
        var current = Build();
        if (Environment.GetEnvironmentVariable("UPDATE_GOLDEN") == "1")
        {
            var source = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Golden", "vectors.json"));
            File.WriteAllText(source, JsonSerializer.Serialize(current, Json) + "\n");
            return;
        }

        var committed = JsonSerializer.Deserialize<VectorSet>(File.ReadAllText(VectorFile))!;
        committed.Ciphertexts.Should().BeEquivalentTo(current.Ciphertexts, o => o.WithStrictOrdering());
        committed.BlindIndexes.Should().BeEquivalentTo(current.BlindIndexes, o => o.WithStrictOrdering());
    }

    [Fact]
    public void Committed_ciphertexts_decrypt_and_follow_the_written_spec()
    {
        var committed = JsonSerializer.Deserialize<VectorSet>(File.ReadAllText(VectorFile))!;
        committed.Ciphertexts.Should().HaveCount(CipherInputs.Length);

        foreach (var v in committed.Ciphertexts)
        {
            var bytes = Convert.FromHexString(v.Ciphertext);
            var context = new EncryptionContext(v.Table, v.Column, v.RowKey);

            Encoding.UTF8.GetString(FieldEncryptor.Open(Convert.FromHexString(v.Key), bytes, context)).Should().Be(v.Plaintext, v.Name);
            DecryptFromSpec(bytes, v).Should().Be(v.Plaintext, v.Name);
        }
    }

    private static VectorSet Build()
    {
        var ciphertexts = CipherInputs.Select(i =>
        {
            var sealedValue = FieldEncryptor.Seal(Key, DataKeyId, Convert.FromHexString(i.Nonce), Encoding.UTF8.GetBytes(i.Plaintext), new EncryptionContext(i.Table, i.Column, i.Row));
            return new CipherVector(i.Name, Convert.ToHexStringLower(Key), DataKeyId.ToString("D"), i.Nonce, i.Table, i.Column, i.Row, i.Plaintext, Convert.ToHexStringLower(sealedValue));
        }).ToList();

        var indexes = IndexInputs.Select(i =>
        {
            var columnKey = BlindIndexer.DeriveColumnKey(Key, i.Table, i.Column);
            var normalized = Normalizer(i.Normalizer)(i.Input);
            return new IndexVector(i.Name, Convert.ToHexStringLower(Key), i.Table, i.Column, i.Bits, i.Normalizer, i.Input, normalized, BlindIndexer.Compute(columnKey, normalized, i.Bits));
        }).ToList();

        return new VectorSet(ciphertexts, indexes);
    }

    private static Func<string, string> Normalizer(string name) => name switch
    {
        "digits" => TextNormalizers.DigitsOnly,
        "turkish" => TextNormalizers.TurkishCaseFold,
        "email" => TextNormalizers.Email,
        _ => TextNormalizers.None,
    };

    /// <summary>Re-implements decryption from docs/ciphertext-format.md without calling the library's encoder.</summary>
    private static string DecryptFromSpec(byte[] c, CipherVector v)
    {
        c[0].Should().Be(1);
        new Guid(c.AsSpan(1, 16), bigEndian: true).Should().Be(Guid.Parse(v.DataKeyId));
        Convert.ToHexStringLower(c.AsSpan(17, 12)).Should().Be(v.Nonce);

        using var aad = new MemoryStream();
        aad.Write(c, 0, 17);
        aad.Write("fc-ctx-1"u8);
        WriteField(aad, v.Table);
        WriteField(aad, v.Column);
        aad.WriteByte(v.RowKey is null ? (byte)0 : (byte)1);
        if (v.RowKey is not null)
        {
            WriteField(aad, v.RowKey);
        }

        var plaintext = new byte[c.Length - 45];
        using var aes = new AesGcm(Convert.FromHexString(v.Key), 16);
        aes.Decrypt(c.AsSpan(17, 12), c.AsSpan(29, plaintext.Length), c.AsSpan(c.Length - 16), plaintext, aad.ToArray());
        return Encoding.UTF8.GetString(plaintext);

        static void WriteField(Stream stream, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            stream.Write(length);
            stream.Write(bytes);
        }
    }

    public sealed record VectorSet(List<CipherVector> Ciphertexts, List<IndexVector> BlindIndexes);

    public sealed record CipherVector(string Name, string Key, string DataKeyId, string Nonce, string Table, string Column, string? RowKey, string Plaintext, string Ciphertext);

    public sealed record IndexVector(string Name, string RootKey, string Table, string Column, int Bits, string Normalizer, string Input, string Normalized, long Value);
}
