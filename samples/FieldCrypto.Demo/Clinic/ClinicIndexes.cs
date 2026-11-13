using FieldCrypto.BlindIndexing;

namespace FieldCrypto.Demo.Clinic;

/// <summary>
/// Blind index definitions. National id and e-mail use 16 bits: at 100,000 rows that is ~1.5 false positives per lookup
/// (measured, docs/benchmarks.md) and at 1,000,000 rows ~15, the planned ceiling. Surnames repeat anyway, so 12 bits
/// costs little extra filtering and keeps buckets mixed.
/// </summary>
public static class ClinicIndexes
{
    public static readonly BlindIndexDefinition NationalId = new("patients", "national_id", 16, TextNormalizers.DigitsOnly);
    public static readonly BlindIndexDefinition Surname = new("patients", "surname", 12, TextNormalizers.TurkishCaseFold);
    public static readonly BlindIndexDefinition Email = new("patients", "email", 16, TextNormalizers.Email);
}
