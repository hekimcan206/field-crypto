using System.Text.RegularExpressions;

namespace FieldCrypto.Dapper;

/// <summary>
/// Table and column names are interpolated into SQL (they cannot be parameters), so only plain lower-case identifiers
/// are accepted, optionally schema-qualified, and they are always double-quoted.
/// </summary>
internal static partial class SqlIdentifier
{
    public static string Quote(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        if (!Pattern().IsMatch(identifier))
        {
            throw new ArgumentException($"'{identifier}' is not an allowed identifier (lower-case letters, digits, underscore; optional schema prefix).", nameof(identifier));
        }

        return string.Join('.', identifier.Split('.').Select(part => $"\"{part}\""));
    }

    [GeneratedRegex("^[a-z_][a-z0-9_]{0,62}(\\.[a-z_][a-z0-9_]{0,62})?$")]
    private static partial Regex Pattern();
}
