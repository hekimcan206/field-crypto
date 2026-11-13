using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FieldCrypto.DevKms;

/// <summary>
/// Versioned AES-256 master keys, held in memory and optionally persisted. Ciphertexts name their version, like OCI
/// Vault ciphertexts do, so decrypt needs only the key OCID.
/// </summary>
/// <remarks>Ciphertext: base64(<c>0x01 | u32 version | 12-byte nonce | AES-256-GCM ciphertext | 16-byte tag</c>).</remarks>
public sealed class MasterKeyStore
{
    private readonly Lock _gate = new();
    private readonly string? _path;
    private readonly Dictionary<string, List<byte[]>> _keys;

    public MasterKeyStore(IEnumerable<string> keyIds, string? statePath)
    {
        _path = statePath;
        if (statePath is not null && File.Exists(statePath))
        {
            var state = JsonSerializer.Deserialize<Dictionary<string, List<string>>>(File.ReadAllText(statePath)) ?? [];
            _keys = state.ToDictionary(kv => kv.Key, kv => kv.Value.Select(Convert.FromBase64String).ToList(), StringComparer.Ordinal);
        }
        else
        {
            _keys = new Dictionary<string, List<byte[]>>(StringComparer.Ordinal);
        }

        foreach (var id in keyIds.Where(id => !_keys.ContainsKey(id)))
        {
            _keys[id] = [RandomNumberGenerator.GetBytes(32)];
        }

        Persist();
    }

    public static string VersionId(string keyId, int number) =>
        string.Create(CultureInfo.InvariantCulture, $"{keyId.Replace("ocid1.key.", "ocid1.keyversion.", StringComparison.Ordinal)}.{number}");

    public bool Exists(string keyId)
    {
        lock (_gate)
        {
            return _keys.ContainsKey(keyId);
        }
    }

    public string? CurrentVersion(string keyId)
    {
        lock (_gate)
        {
            return _keys.TryGetValue(keyId, out var versions) ? VersionId(keyId, versions.Count) : null;
        }
    }

    public string? AddVersion(string keyId)
    {
        lock (_gate)
        {
            if (!_keys.TryGetValue(keyId, out var versions))
            {
                return null;
            }

            versions.Add(RandomNumberGenerator.GetBytes(32));
            Persist();
            return VersionId(keyId, versions.Count);
        }
    }

    public (string Ciphertext, string VersionId)? Encrypt(string keyId, byte[] plaintext, IReadOnlyDictionary<string, string>? associatedData)
    {
        byte[] key;
        int number;
        lock (_gate)
        {
            if (!_keys.TryGetValue(keyId, out var versions))
            {
                return null;
            }

            number = versions.Count;
            key = versions[^1];
        }

        var blob = new byte[1 + 4 + 12 + plaintext.Length + 16];
        blob[0] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(1), (uint)number);
        RandomNumberGenerator.Fill(blob.AsSpan(5, 12));
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(blob.AsSpan(5, 12), plaintext, blob.AsSpan(17, plaintext.Length), blob.AsSpan(17 + plaintext.Length), Aad(keyId, associatedData));
        return (Convert.ToBase64String(blob), VersionId(keyId, number));
    }

    /// <summary>Null when the key does not exist; throws <see cref="CryptographicException"/> when the ciphertext is rejected.</summary>
    public (byte[] Plaintext, string VersionId)? Decrypt(string keyId, string ciphertext, IReadOnlyDictionary<string, string>? associatedData)
    {
        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(ciphertext);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("Ciphertext is not base64.", ex);
        }

        if (blob.Length < 1 + 4 + 12 + 16 || blob[0] != 1)
        {
            throw new CryptographicException("Ciphertext is malformed.");
        }

        var number = (int)BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(1));
        byte[] key;
        lock (_gate)
        {
            if (!_keys.TryGetValue(keyId, out var versions))
            {
                return null;
            }

            if (number < 1 || number > versions.Count)
            {
                throw new CryptographicException("Ciphertext names a key version that does not exist.");
            }

            key = versions[number - 1];
        }

        var plaintext = new byte[blob.Length - 33];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(blob.AsSpan(5, 12), blob.AsSpan(17, plaintext.Length), blob.AsSpan(blob.Length - 16), plaintext, Aad(keyId, associatedData));
        return (plaintext, VersionId(keyId, number));
    }

    private static byte[] Aad(string keyId, IReadOnlyDictionary<string, string>? associatedData)
    {
        var builder = new StringBuilder("devkms-v1\n").Append(keyId).Append('\n');
        foreach (var (name, value) in (associatedData ?? new Dictionary<string, string>()).OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            builder.Append(name.Length).Append(':').Append(name).Append('=').Append(value.Length).Append(':').Append(value).Append('\n');
        }

        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private void Persist()
    {
        if (_path is null)
        {
            return;
        }

        var json = JsonSerializer.Serialize(_keys.ToDictionary(kv => kv.Key, kv => kv.Value.Select(Convert.ToBase64String).ToList()));
        var temp = _path + ".tmp";
        File.WriteAllText(temp, json);
        File.Move(temp, _path, overwrite: true);
    }
}
