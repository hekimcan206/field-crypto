using System.Linq.Expressions;
using FieldCrypto.BlindIndexing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace FieldCrypto.EntityFrameworkCore;

/// <summary>Model configuration for encrypted properties and their blind indexes.</summary>
public static class FieldCryptoModelExtensions
{
    internal const string EncryptedAnnotation = "FieldCrypto:Encrypted";
    internal const string BlindIndexAnnotation = "FieldCrypto:BlindIndex";

    /// <summary>
    /// Stores the string property as a FieldCrypto ciphertext (bytea / varbinary).
    /// </summary>
    /// <remarks>
    /// The context is fixed at model-building time to table and column (the arguments, or the mapped names when they
    /// are already configured). EF Core value converters see one value and no row, so ciphertexts are column-bound,
    /// not row-bound: a ciphertext copied to another row of the same column still decrypts. Use the Dapper helpers when
    /// row binding matters. Equality filters on the property do not work (every encryption is randomised); query
    /// through the blind index instead.
    /// </remarks>
    public static PropertyBuilder IsEncrypted(this PropertyBuilder property, FieldEncryptor encryptor, string? table = null, string? column = null)
    {
        ArgumentNullException.ThrowIfNull(property);
        ArgumentNullException.ThrowIfNull(encryptor);
        var metadata = property.Metadata;
        if (metadata.ClrType != typeof(string))
        {
            throw new InvalidOperationException($"{metadata.DeclaringType.DisplayName()}.{metadata.Name} is not a string; only string properties can be encrypted.");
        }

        var context = new EncryptionContext(
            table ?? (metadata.DeclaringType as Microsoft.EntityFrameworkCore.Metadata.IReadOnlyEntityType)?.GetTableName() ?? metadata.DeclaringType.ShortName(),
            column ?? metadata.GetColumnName());
        property.HasConversion(new EncryptedStringConverter(encryptor, context));
        property.HasAnnotation(EncryptedAnnotation, context.ToString());
        return property;
    }

    /// <summary>
    /// Declares <paramref name="indexProperty"/> as the blind index of <paramref name="sourceProperty"/>. Register
    /// <see cref="BlindIndexInterceptor"/> so the index is computed on every insert and update.
    /// </summary>
    public static EntityTypeBuilder<TEntity> HasBlindIndex<TEntity>(
        this EntityTypeBuilder<TEntity> entity,
        Expression<Func<TEntity, string?>> sourceProperty,
        Expression<Func<TEntity, long?>> indexProperty,
        BlindIndexDefinition definition)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(entity);
        ArgumentNullException.ThrowIfNull(sourceProperty);
        ArgumentNullException.ThrowIfNull(definition);
        var source = MemberName(sourceProperty);
        entity.Property(indexProperty).HasAnnotation(BlindIndexAnnotation, new BlindIndexBinding(source, definition));
        entity.HasIndex(MemberName(indexProperty));
        return entity;
    }

    private static string MemberName<TEntity, TValue>(Expression<Func<TEntity, TValue>> expression) =>
        expression.Body is MemberExpression member
            ? member.Member.Name
            : throw new ArgumentException("Expected a property access such as p => p.NationalId.", nameof(expression));

    private sealed class EncryptedStringConverter(FieldEncryptor encryptor, EncryptionContext context)
        : ValueConverter<string, byte[]>(
            plaintext => encryptor.Encrypt(plaintext, context),
            ciphertext => encryptor.Decrypt(ciphertext, context));
}

/// <summary>Annotation value linking a blind index property to its source property and definition.</summary>
public sealed record BlindIndexBinding(string SourceProperty, BlindIndexDefinition Definition);
