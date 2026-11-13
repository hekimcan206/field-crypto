namespace FieldCrypto.BlindIndexing;

/// <summary>
/// One blind index: which column it belongs to (the per-column key is derived from it), how many bits are kept, and
/// how input is normalised. All three are part of the stored values: changing any of them means recomputing the index.
/// </summary>
public sealed class BlindIndexDefinition
{
    public BlindIndexDefinition(string table, string column, int bits, Func<string, string>? normalizer = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(table);
        ArgumentException.ThrowIfNullOrWhiteSpace(column);
        ArgumentOutOfRangeException.ThrowIfLessThan(bits, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(bits, 32);
        Table = table;
        Column = column;
        Bits = bits;
        Normalizer = normalizer ?? TextNormalizers.None;
    }

    public string Table { get; }

    public string Column { get; }

    /// <summary>
    /// Kept bits of HMAC-SHA256 (1..32), stored as a non-negative <c>bigint</c>-compatible integer. Fewer bits mean more
    /// false positives per query and less for an attacker to learn from equal index values; see <see cref="BlindIndexPlanner"/>.
    /// </summary>
    public int Bits { get; }

    public Func<string, string> Normalizer { get; }

    public override string ToString() => $"{Table}.{Column} ({Bits} bits)";
}
