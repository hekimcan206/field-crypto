namespace FieldCrypto;

/// <summary>
/// Version 1 field ciphertext:
/// <code>
/// offset  size  content
///      0     1  format version (0x01)
///      1    16  data key id (UUID, RFC 9562 byte order, identical to PostgreSQL uuid_send)
///     17    12  random nonce
///     29     n  AES-256-GCM ciphertext (n = plaintext length)
///   29+n    16  GCM tag
/// </code>
/// The 17 header bytes are part of the associated data, so changing the version or pointing the ciphertext at
/// another data key is detected like any other tampering. The format is specified in docs/ciphertext-format.md.
/// </summary>
public static class CiphertextLayout
{
    public const byte Version1 = 0x01;
    public const int VersionSize = 1;
    public const int DataKeyIdSize = 16;
    public const int HeaderSize = VersionSize + DataKeyIdSize;
    public const int NonceSize = 12;
    public const int TagSize = 16;

    /// <summary>Bytes added to every plaintext: 45.</summary>
    public const int Overhead = HeaderSize + NonceSize + TagSize;

    /// <summary>1-based offset of the data key id, for SQL <c>substring(col from 2 for 16)</c>.</summary>
    public const int SqlDataKeyIdOffset = 2;

    /// <summary>Reads the data key id without decrypting. Used by rotation jobs to find rows on retired keys.</summary>
    public static bool TryReadDataKeyId(ReadOnlySpan<byte> ciphertext, out Guid dataKeyId)
    {
        if (ciphertext.Length < Overhead || ciphertext[0] != Version1)
        {
            dataKeyId = Guid.Empty;
            return false;
        }

        dataKeyId = new Guid(ciphertext.Slice(VersionSize, DataKeyIdSize), bigEndian: true);
        return true;
    }

    internal static void WriteDataKeyId(Span<byte> destination, Guid id)
    {
        if (!id.TryWriteBytes(destination, bigEndian: true, out _))
        {
            throw new InvalidOperationException("Destination too small for a UUID.");
        }
    }
}
