using System.Security.Cryptography;
using System.Text;
using FieldCrypto.Keys;

namespace FieldCrypto;

/// <summary>
/// Encrypts and decrypts single field values with AES-256-GCM under the key ring's data keys.
/// Thread-safe; register one instance per key ring.
/// </summary>
/// <remarks>
/// Null is not encrypted (callers store SQL NULL), so whether a value is present is visible to anyone who can read
/// the table. The ciphertext length is the plaintext's UTF-8 length plus <see cref="CiphertextLayout.Overhead"/>, so
/// length is visible too; pad before encrypting if length itself is sensitive.
/// </remarks>
public sealed class FieldEncryptor(KeyRing keyRing)
{
    private readonly KeyRing _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));

    public KeyRing KeyRing => _keyRing;

    public byte[] Encrypt(string plaintext, EncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Encrypt(Encoding.UTF8.GetBytes(plaintext), context);
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, EncryptionContext context)
    {
        var lease = _keyRing.Acquire();
        return Seal(lease.Key, lease.Id, plaintext, context);
    }

    public async ValueTask<byte[]> EncryptAsync(string plaintext, EncryptionContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var lease = await _keyRing.AcquireAsync(cancellationToken);
        return Seal(lease.Key, lease.Id, Encoding.UTF8.GetBytes(plaintext), context);
    }

    public string Decrypt(ReadOnlySpan<byte> ciphertext, EncryptionContext context) =>
        Encoding.UTF8.GetString(DecryptBytes(ciphertext, context));

    public byte[] DecryptBytes(ReadOnlySpan<byte> ciphertext, EncryptionContext context)
    {
        var dataKeyId = ReadHeader(ciphertext);
        return Open(_keyRing.GetDataKey(dataKeyId), ciphertext, context);
    }

    public async ValueTask<string> DecryptAsync(ReadOnlyMemory<byte> ciphertext, EncryptionContext context, CancellationToken cancellationToken = default)
    {
        var dataKeyId = ReadHeader(ciphertext.Span);
        var key = await _keyRing.GetDataKeyAsync(dataKeyId, cancellationToken);
        return Encoding.UTF8.GetString(Open(key, ciphertext.Span, context));
    }

    internal static byte[] Seal(ReadOnlySpan<byte> key, Guid dataKeyId, ReadOnlySpan<byte> plaintext, EncryptionContext context)
    {
        Span<byte> nonce = stackalloc byte[CiphertextLayout.NonceSize];
        RandomNumberGenerator.Fill(nonce);
        return Seal(key, dataKeyId, nonce, plaintext, context);
    }

    /// <summary>Deterministic core with a caller-supplied nonce. Only tests (golden vectors) pass a fixed nonce.</summary>
    internal static byte[] Seal(ReadOnlySpan<byte> key, Guid dataKeyId, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, EncryptionContext context)
    {
        var output = new byte[CiphertextLayout.Overhead + plaintext.Length];
        var span = output.AsSpan();
        span[0] = CiphertextLayout.Version1;
        CiphertextLayout.WriteDataKeyId(span.Slice(CiphertextLayout.VersionSize, CiphertextLayout.DataKeyIdSize), dataKeyId);
        nonce.CopyTo(span.Slice(CiphertextLayout.HeaderSize, CiphertextLayout.NonceSize));

        var body = CiphertextLayout.HeaderSize + CiphertextLayout.NonceSize;
        using var aes = new AesGcm(key, CiphertextLayout.TagSize);
        aes.Encrypt(
            nonce,
            plaintext,
            span.Slice(body, plaintext.Length),
            span[(body + plaintext.Length)..],
            AssociatedData(span[..CiphertextLayout.HeaderSize], context));
        return output;
    }

    internal static byte[] Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, EncryptionContext context)
    {
        var body = CiphertextLayout.HeaderSize + CiphertextLayout.NonceSize;
        var length = ciphertext.Length - CiphertextLayout.Overhead;
        var plaintext = new byte[length];
        try
        {
            using var aes = new AesGcm(key, CiphertextLayout.TagSize);
            aes.Decrypt(
                ciphertext.Slice(CiphertextLayout.HeaderSize, CiphertextLayout.NonceSize),
                ciphertext.Slice(body, length),
                ciphertext[(body + length)..],
                plaintext,
                AssociatedData(ciphertext[..CiphertextLayout.HeaderSize], context));
        }
        catch (CryptographicException ex)
        {
            throw new FieldDecryptionException(
                FieldDecryptionFailure.AuthenticationFailed,
                $"Ciphertext for {context.Table}.{context.Column} did not authenticate: altered, or written for another column or row.",
                ex);
        }

        return plaintext;
    }

    private static Guid ReadHeader(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < CiphertextLayout.Overhead)
        {
            throw new FieldDecryptionException(FieldDecryptionFailure.Malformed, "Ciphertext is shorter than the format overhead.");
        }

        if (ciphertext[0] != CiphertextLayout.Version1)
        {
            throw new FieldDecryptionException(FieldDecryptionFailure.UnsupportedVersion, $"Unsupported ciphertext format version {ciphertext[0]}.");
        }

        CiphertextLayout.TryReadDataKeyId(ciphertext, out var id);
        return id;
    }

    private static byte[] AssociatedData(ReadOnlySpan<byte> header, EncryptionContext context)
    {
        var encoded = context.Encode();
        var aad = new byte[header.Length + encoded.Length];
        header.CopyTo(aad);
        encoded.CopyTo(aad.AsSpan(header.Length));
        return aad;
    }
}
