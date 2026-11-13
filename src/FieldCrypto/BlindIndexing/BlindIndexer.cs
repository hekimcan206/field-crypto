using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using FieldCrypto.Keys;

namespace FieldCrypto.BlindIndexing;

/// <summary>
/// Computes blind indexes: <c>truncate(HMAC-SHA256(columnKey, normalize(value)), bits)</c>, where the column key is
/// <c>HKDF-SHA256(rootKey, info = "field-crypto/blind-index/v1|table|column")</c>.
/// </summary>
/// <remarks>
/// A separate key per column means the same national id in two tables (or the same text in two columns) produces
/// unrelated index values, so an attacker cannot join tables on them. The root key is a data key in the key store,
/// wrapped by the KEK like the others, so a KEK rotation covers it too.
/// </remarks>
public sealed class BlindIndexer(KeyRing keyRing)
{
    private const string InfoPrefix = "field-crypto/blind-index/v1|";
    private readonly KeyRing _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
    private readonly ConcurrentDictionary<(string Table, string Column), byte[]> _columnKeys = new();

    /// <summary>Index value of <paramref name="value"/>, in [0, 2^bits).</summary>
    public long Compute(string value, BlindIndexDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(definition);
        var key = _columnKeys.GetOrAdd((definition.Table, definition.Column), DeriveColumnKey);
        return Compute(key, definition.Normalizer(value), definition.Bits);
    }

    /// <summary>Same normalisation as the index, for the post-decryption equality check that removes false positives.</summary>
    public static bool Matches(string candidatePlaintext, string query, BlindIndexDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        return string.Equals(definition.Normalizer(candidatePlaintext), definition.Normalizer(query), StringComparison.Ordinal);
    }

    internal static long Compute(ReadOnlySpan<byte> columnKey, string normalized, int bits)
    {
        Span<byte> mac = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(columnKey, Encoding.UTF8.GetBytes(normalized), mac);
        var prefix = BinaryPrimitives.ReadUInt32BigEndian(mac);
        return prefix >> (32 - bits);
    }

    internal static byte[] DeriveColumnKey(ReadOnlySpan<byte> rootKey, string table, string column) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, rootKey.ToArray(), 32, salt: [], info: Encoding.UTF8.GetBytes(InfoPrefix + table + "|" + column));

    private byte[] DeriveColumnKey((string Table, string Column) column) =>
        DeriveColumnKey(_keyRing.GetBlindIndexRootKey(), column.Table, column.Column);
}
