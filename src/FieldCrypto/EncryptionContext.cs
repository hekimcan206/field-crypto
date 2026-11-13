using System.Buffers.Binary;
using System.Text;

namespace FieldCrypto;

/// <summary>
/// Where a ciphertext belongs. It is authenticated as AES-GCM associated data, so a ciphertext copied to another
/// column (or, when <see cref="RowKey"/> is set, to another row) fails to decrypt instead of silently showing the
/// wrong person's value.
/// </summary>
public readonly record struct EncryptionContext
{
    private const string Magic = "fc-ctx-1";

    public EncryptionContext(string table, string column, string? rowKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(table);
        ArgumentException.ThrowIfNullOrWhiteSpace(column);
        if (rowKey is not null)
        {
            ArgumentException.ThrowIfNullOrEmpty(rowKey);
        }

        Table = table;
        Column = column;
        RowKey = rowKey;
    }

    public string Table { get; }

    public string Column { get; }

    /// <summary>Primary key of the row, when the caller knows it at write time. Null binds to the column only.</summary>
    public string? RowKey { get; }

    public bool IsRowBound => RowKey is not null;

    public EncryptionContext WithRow(string rowKey) => new(Table, Column, rowKey);

    public override string ToString() => RowKey is null ? $"{Table}.{Column}" : $"{Table}.{Column}[{RowKey}]";

    /// <summary>
    /// Length-prefixed, so ("ab", "c") and ("a", "bc") never encode to the same bytes. A missing row key and an
    /// empty one are different too (the flag byte), although empty row keys are rejected anyway.
    /// </summary>
    internal byte[] Encode()
    {
        var length = Magic.Length + Field(Table) + Field(Column) + 1 + (RowKey is null ? 0 : Field(RowKey));
        var buffer = new byte[length];
        var span = buffer.AsSpan();
        var offset = Encoding.ASCII.GetBytes(Magic, span);
        offset += Write(span[offset..], Table);
        offset += Write(span[offset..], Column);
        span[offset++] = RowKey is null ? (byte)0 : (byte)1;
        if (RowKey is not null)
        {
            Write(span[offset..], RowKey);
        }

        return buffer;

        static int Field(string value) => 4 + Encoding.UTF8.GetByteCount(value);

        static int Write(Span<byte> destination, string value)
        {
            var written = Encoding.UTF8.GetBytes(value, destination[4..]);
            BinaryPrimitives.WriteInt32BigEndian(destination, written);
            return 4 + written;
        }
    }
}
