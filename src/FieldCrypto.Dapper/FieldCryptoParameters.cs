using System.Data;
using Dapper;
using FieldCrypto.BlindIndexing;

namespace FieldCrypto.Dapper;

/// <summary>
/// Dapper parameters for encrypted columns. Encryption is explicit at the call site, with the row key in hand, so
/// Dapper code gets row-bound ciphertexts (a value copied to another row fails to decrypt), which EF Core value
/// converters cannot offer.
/// </summary>
public static class FieldCryptoParameters
{
    /// <summary>Adds <paramref name="plaintext"/> encrypted for <paramref name="context"/>; null stays SQL NULL.</summary>
    public static DynamicParameters AddEncrypted(this DynamicParameters parameters, string name, string? plaintext, FieldEncryptor encryptor, EncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(encryptor);
        parameters.Add(name, plaintext is null ? null : encryptor.Encrypt(plaintext, context), DbType.Binary);
        return parameters;
    }

    /// <summary>Adds the blind index of <paramref name="plaintext"/>; null stays SQL NULL.</summary>
    public static DynamicParameters AddBlindIndex(this DynamicParameters parameters, string name, string? plaintext, BlindIndexer indexer, BlindIndexDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(indexer);
        parameters.Add(name, plaintext is null ? null : indexer.Compute(plaintext, definition), DbType.Int64);
        return parameters;
    }

    /// <summary>Decrypts a nullable column value.</summary>
    public static string? DecryptOrNull(this FieldEncryptor encryptor, byte[]? ciphertext, EncryptionContext context)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        return ciphertext is null ? null : encryptor.Decrypt(ciphertext, context);
    }
}
