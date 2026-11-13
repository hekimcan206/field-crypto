using System.Security.Cryptography;

namespace FieldCrypto;

public enum FieldDecryptionFailure
{
    /// <summary>Too short, or not produced by this library.</summary>
    Malformed,

    /// <summary>A format version this build does not understand.</summary>
    UnsupportedVersion,

    /// <summary>The data key id is not in the key store (destroyed, or a ciphertext from another system).</summary>
    UnknownDataKey,

    /// <summary>The KMS refused to unwrap the data key (KEK version destroyed, wrapped key altered, wrong KMS).</summary>
    DataKeyUnwrapFailed,

    /// <summary>
    /// The GCM tag did not verify: the bytes were changed, or the ciphertext was moved to another column or row
    /// than the one it was written for.
    /// </summary>
    AuthenticationFailed,
}

/// <summary>Decryption failed. The message never contains plaintext or key material.</summary>
public sealed class FieldDecryptionException : CryptographicException
{
    public FieldDecryptionException()
    {
    }

    public FieldDecryptionException(string message)
        : base(message)
    {
    }

    public FieldDecryptionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public FieldDecryptionException(FieldDecryptionFailure failure, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Failure = failure;
    }

    public FieldDecryptionFailure Failure { get; }
}
