namespace FieldCrypto.Demo.Clinic;

/// <summary>A synthetic patient. Personal data is encrypted; blind indexes make three of the fields searchable.</summary>
public sealed class Patient
{
    public Guid Id { get; set; }

    /// <summary>T.C. Kimlik No (Turkish national identity number, 11 digits). Synthetic, checksum-valid.</summary>
    public string NationalId { get; set; } = string.Empty;

    public long? NationalIdIndex { get; set; }

    public string FullName { get; set; } = string.Empty;

    /// <summary>Searchable surname, Turkish case-insensitive.</summary>
    public string Surname { get; set; } = string.Empty;

    public long? SurnameIndex { get; set; }

    public string? Email { get; set; }

    public long? EmailIndex { get; set; }

    public string? Phone { get; set; }

    /// <summary>Not personal data on its own: kept in plaintext so it can be filtered and sorted.</summary>
    public int BirthYear { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>A lab result note written through Dapper, encrypted row-bound (the context includes the row id).</summary>
public sealed record LabResult(long Id, Guid PatientId, string TestCode, string Note);
