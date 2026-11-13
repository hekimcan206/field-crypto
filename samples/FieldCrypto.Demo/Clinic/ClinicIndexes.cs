using FieldCrypto.BlindIndexing;

namespace FieldCrypto.Demo.Clinic;

/// <summary>
/// Blind index definitions. Bit lengths come from <see cref="BlindIndexPlanner"/> for a planned 1,000,000 patients
/// (docs/blind-index.md): national id 16 bits (~15 false positives per lookup, ~15 patients share each index value),
/// e-mail 16 bits, surname 12 bits (surnames repeat, so a coarser index still returns few candidates per name).
/// </summary>
public static class ClinicIndexes
{
    public static readonly BlindIndexDefinition NationalId = new("patients", "national_id", 16, TextNormalizers.DigitsOnly);
    public static readonly BlindIndexDefinition Surname = new("patients", "surname", 12, TextNormalizers.TurkishCaseFold);
    public static readonly BlindIndexDefinition Email = new("patients", "email", 16, TextNormalizers.Email);
}
