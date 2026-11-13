using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using FieldCrypto.BlindIndexing;
using FieldCrypto.Keys;
using FieldCrypto.Kms;
using FieldCrypto.Oci;

namespace FieldCrypto.Benchmarks;

/// <summary>Per-field CPU cost with a warm data key cache: what an application pays on every read and write.</summary>
[MemoryDiagnoser]
public class FieldBenchmarks
{
    private static readonly EncryptionContext Context = new("patients", "national_id");
    private static readonly EncryptionContext RowContext = new("lab_results", "note", "123456");
    private static readonly BlindIndexDefinition Index = new("patients", "national_id", 16, TextNormalizers.DigitsOnly);
    private static readonly BlindIndexDefinition Surname = new("patients", "surname", 12, TextNormalizers.TurkishCaseFold);
    private KeyRing _ring = null!;
    private FieldEncryptor _encryptor = null!;
    private BlindIndexer _indexer = null!;
    private byte[] _nationalIdCipher = null!;
    private byte[] _noteCipher = null!;
    private string _note = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ring = new KeyRing(LocalKeyEncryptionService.CreateEphemeral(), new InMemoryDataKeyStore(), new KeyRingOptions { MaxMessagesPerDataKey = 1L << 32 });
        _encryptor = new FieldEncryptor(_ring);
        _indexer = new BlindIndexer(_ring);
        _note = new string('x', 1024);
        _nationalIdCipher = _encryptor.Encrypt("10000000146", Context);
        _noteCipher = _encryptor.Encrypt(_note, RowContext);
        _indexer.Compute("10000000146", Index);
    }

    [GlobalCleanup]
    public void Cleanup() => _ring.Dispose();

    [Benchmark(Description = "encrypt 11-char national id")]
    public byte[] EncryptNationalId() => _encryptor.Encrypt("10000000146", Context);

    [Benchmark(Description = "decrypt 11-char national id")]
    public string DecryptNationalId() => _encryptor.Decrypt(_nationalIdCipher, Context);

    [Benchmark(Description = "encrypt 1 KiB note (row-bound)")]
    public byte[] EncryptNote() => _encryptor.Encrypt(_note, RowContext);

    [Benchmark(Description = "decrypt 1 KiB note (row-bound)")]
    public string DecryptNote() => _encryptor.Decrypt(_noteCipher, RowContext);

    [Benchmark(Description = "blind index, digits (16 bits)")]
    public long BlindIndexNationalId() => _indexer.Compute("100 000 001 46", Index);

    [Benchmark(Description = "blind index, Turkish fold (12 bits)")]
    public long BlindIndexSurname() => _indexer.Compute("IŞIKOĞLU", Surname);
}

/// <summary>The cost of a KMS call that never leaves the process, and of signing one OCI request.</summary>
[MemoryDiagnoser]
public class KmsCpuBenchmarks
{
    private static readonly KeyWrapContext Context = new(Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8057"), "data");
    private readonly LocalKeyEncryptionService _local = LocalKeyEncryptionService.CreateEphemeral();
    private readonly RSA _rsa = RSA.Create(2048);
    private byte[] _key = null!;
    private byte[] _wrapped = null!;

    [GlobalSetup]
    public void Setup()
    {
        _key = RandomNumberGenerator.GetBytes(32);
        _wrapped = _local.Wrap(_key, Context).Ciphertext;
    }

    [Benchmark(Description = "local KEK wrap")]
    public WrappedDataKey LocalWrap() => _local.Wrap(_key, Context);

    [Benchmark(Description = "local KEK unwrap")]
    public byte[] LocalUnwrap() => _local.Unwrap(_wrapped, Context);

    [Benchmark(Description = "OCI request signature (RSA-2048)")]
    public string OciSign()
    {
        var headers = new Dictionary<string, string>
        {
            ["date"] = "Fri, 13 Nov 2026 10:00:00 GMT",
            ["host"] = "kms.example.test",
            ["content-length"] = "120",
            ["content-type"] = "application/json",
            ["x-content-sha256"] = "V9Z20UJTvkvpJ50flBzKE32+6m2zJjweHpDMX/U4Uy0=",
        };
        return OciSignature.Sign(OciSignature.BuildSigningString("POST", "/20180608/decrypt", OciSignature.HeadersWithBody, n => headers.GetValueOrDefault(n)), _rsa);
    }
}
