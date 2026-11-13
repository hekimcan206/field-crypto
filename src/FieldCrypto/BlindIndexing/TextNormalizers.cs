using System.Globalization;
using System.Text;

namespace FieldCrypto.BlindIndexing;

/// <summary>
/// Normalisers decide which inputs a blind index treats as equal. They run before hashing, so changing one after data
/// is written means recomputing the index (it is part of the index definition, like the bit length).
/// </summary>
public static class TextNormalizers
{
    /// <summary>Exact bytes: only identical strings match.</summary>
    public static string None(string value) => value;

    /// <summary>
    /// Case-insensitive match for Turkish text. NFKC, trim, collapse whitespace, then fold all four Turkish i letters
    /// (I, ı, İ, i) to "i" before lower-casing invariantly.
    /// </summary>
    /// <remarks>
    /// Neither culture-invariant nor Turkish-culture lower-casing is enough on its own: invariant maps "İ" to "i̇"
    /// (i + U+0307 combining dot) so "İZMİR" and "izmir" differ, and tr-TR maps "I" to "ı" so a name typed on a
    /// non-Turkish keyboard ("IREM") misses "İrem". Folding the four letters together makes both match, at the cost of
    /// also equating "ısı" and "isi", which a blind index tolerates because the application re-checks every candidate
    /// after decryption anyway.
    /// </remarks>
    public static string TurkishCaseFold(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var normalized = value.Normalize(NormalizationForm.FormKC);
        var builder = new StringBuilder(normalized.Length);
        var pendingSpace = false;
        foreach (var c in normalized)
        {
            if (char.IsWhiteSpace(c))
            {
                pendingSpace = builder.Length > 0;
                continue;
            }

            if (c == '̇' && builder.Length > 0 && builder[^1] == 'i')
            {
                continue; // combining dot above left over from a decomposed "İ"
            }

            if (pendingSpace)
            {
                builder.Append(' ');
                pendingSpace = false;
            }

            builder.Append(c switch
            {
                'I' or 'ı' or 'İ' => 'i',
                _ => char.ToLowerInvariant(c),
            });
        }

        return builder.ToString();
    }

    /// <summary>
    /// E-mail addresses: trimmed and case-folded as a whole. Strictly the local part is case-sensitive (RFC 5321), but
    /// no mainstream provider treats it that way, and a false positive is filtered after decryption.
    /// </summary>
    public static string Email(string value) => TurkishCaseFold(value).Replace(" ", string.Empty, StringComparison.Ordinal);

    /// <summary>Digits only: phone numbers and identity numbers typed with spaces, dashes or a +90 prefix.</summary>
    public static string DigitsOnly(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (char.IsAsciiDigit(c))
            {
                builder.Append(c);
            }
            else if (char.IsDigit(c))
            {
                builder.Append(((int)char.GetNumericValue(c)).ToString(CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }
}
