using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FieldCrypto.Kms;

/// <summary>
/// A KEK held in process memory (optionally persisted to a JSON file) for development, tests and benchmarks.
/// It behaves like a real KMS where it matters to the library: versions, rotation, associated data, and old
/// versions staying usable for unwrap. It is not a KMS: the key material lives next to the application.
/// </summary>
/// <remarks>
/// Wrapped key layout: <c>u32 version (big-endian) | 12-byte nonce | AES-256-GCM ciphertext | 16-byte tag</c>.
/// The associated data binds the KEK id, version, data key id and purpose.
/// </remarks>
public sealed class LocalKeyEncryptionService : IKeyEncryptionService
{
    private const int KeySize = 32;
    private readonly Lock _gate = new();
    private readonly string? _path;
    private List<byte[]> _versions;

    public LocalKeyEncryptionService(string keyId, IEnumerable<byte[]> versions)
        : this(keyId, versions, path: null)
    {
    }

    private LocalKeyEncryptionService(string keyId, IEnumerable<byte[]> versions, string? path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(versions);
        KeyId = keyId;
        _path = path;
        _versions = versions.Select(v => v.Length == KeySize
            ? v.ToArray()
            : throw new ArgumentException("Every KEK version must be 32 bytes.", nameof(versions))).ToList();
        if (_versions.Count == 0)
        {
            throw new ArgumentException("At least one KEK version is required.", nameof(versions));
        }
    }

    public string KeyId { get; }

    public string CurrentVersion
    {
        get
        {
            lock (_gate)
            {
                return VersionName(_versions.Count);
            }
        }
    }

    public static LocalKeyEncryptionService CreateEphemeral(string keyId = "local-dev-kek") =>
        new(keyId, [RandomNumberGenerator.GetBytes(KeySize)]);

    /// <summary>Loads a key file, or creates one with a fresh random version. Development only: the file is a secret.</summary>
    public static LocalKeyEncryptionService LoadOrCreate(string path, string keyId = "local-dev-kek")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (File.Exists(path))
        {
            var file = JsonSerializer.Deserialize<KeyFile>(File.ReadAllText(path))
                ?? throw new InvalidDataException($"Key file '{path}' is empty.");
            return new LocalKeyEncryptionService(file.KeyId, file.Versions.Select(Convert.FromBase64String), path);
        }

        var service = new LocalKeyEncryptionService(keyId, [RandomNumberGenerator.GetBytes(KeySize)], path);
        service.Persist();
        return service;
    }

    /// <summary>Adds a new KEK version; new wraps use it, older versions still unwrap.</summary>
    public string Rotate()
    {
        lock (_gate)
        {
            _versions = [.. _versions, RandomNumberGenerator.GetBytes(KeySize)];
            Persist();
            return VersionName(_versions.Count);
        }
    }

    public Task<string> GetCurrentKeyVersionAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(CurrentVersion);

    public Task<WrappedDataKey> WrapAsync(ReadOnlyMemory<byte> plaintextKey, KeyWrapContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(Wrap(plaintextKey.Span, context));

    public WrappedDataKey Wrap(ReadOnlySpan<byte> plaintextKey, KeyWrapContext context)
    {
        int number;
        byte[] kek;
        lock (_gate)
        {
            number = _versions.Count;
            kek = _versions[number - 1];
        }

        var blob = new byte[4 + 12 + plaintextKey.Length + 16];
        BinaryPrimitives.WriteUInt32BigEndian(blob, (uint)number);
        var nonce = blob.AsSpan(4, 12);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(kek, 16);
        aes.Encrypt(nonce, plaintextKey, blob.AsSpan(16, plaintextKey.Length), blob.AsSpan(16 + plaintextKey.Length), Aad(number, context));
        return new WrappedDataKey(VersionName(number), blob);
    }

    public Task<byte[]> UnwrapAsync(ReadOnlyMemory<byte> wrappedKey, KeyWrapContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(Unwrap(wrappedKey.Span, context));

    public byte[] Unwrap(ReadOnlySpan<byte> wrappedKey, KeyWrapContext context)
    {
        if (wrappedKey.Length < 4 + 12 + 16)
        {
            throw new CryptographicException("Wrapped key is too short.");
        }

        var number = (int)BinaryPrimitives.ReadUInt32BigEndian(wrappedKey);
        byte[] kek;
        lock (_gate)
        {
            if (number < 1 || number > _versions.Count)
            {
                throw new CryptographicException($"KEK version {number} does not exist.");
            }

            kek = _versions[number - 1];
        }

        var length = wrappedKey.Length - 32;
        var plaintext = new byte[length];
        using var aes = new AesGcm(kek, 16);
        aes.Decrypt(wrappedKey.Slice(4, 12), wrappedKey.Slice(16, length), wrappedKey[^16..], plaintext, Aad(number, context));
        return plaintext;
    }

    private byte[] Aad(int version, KeyWrapContext context) => Encoding.UTF8.GetBytes(
        string.Create(CultureInfo.InvariantCulture, $"fc-local-kek|{KeyId}|{version}|{context.DataKeyId:D}|{context.Purpose}"));

    private static string VersionName(int number) => number.ToString(CultureInfo.InvariantCulture);

    private void Persist()
    {
        if (_path is null)
        {
            return;
        }

        var json = JsonSerializer.Serialize(new KeyFile(KeyId, _versions.Select(Convert.ToBase64String).ToList()));
        var temp = _path + ".tmp";
        File.WriteAllText(temp, json);
        File.Move(temp, _path, overwrite: true);
    }

    private sealed record KeyFile(string KeyId, List<string> Versions);
}
