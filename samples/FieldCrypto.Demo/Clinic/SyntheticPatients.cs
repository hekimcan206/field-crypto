using System.Globalization;
using Bogus;

namespace FieldCrypto.Demo.Clinic;

/// <summary>
/// Deterministic synthetic patients (Bogus, Turkish locale). National ids pass the T.C. Kimlik No checksum so they look
/// like real input to validators and normalisers, but they are generated: no real person's data is used anywhere.
/// </summary>
public static class SyntheticPatients
{
    private static readonly string[] TurkishSurnames =
    [
        "Işık", "Yılmaz", "Kaya", "Demir", "Şahin", "Çelik", "Yıldız", "Yıldırım", "Öztürk", "Aydın",
        "Özdemir", "Arslan", "Doğan", "Kılıç", "Aslan", "Çetin", "Kara", "Koç", "Kurt", "Özkan",
        "İnce", "Irmak", "Güneş", "Erdoğan", "Bulut", "Ilgaz", "İpek", "Uçar", "Ünal", "Ilıca",
    ];

    public static List<Patient> Generate(int count, int seed, DateTimeOffset createdAt)
    {
        var faker = new Faker("tr") { Random = new Randomizer(seed) };
        var used = new HashSet<string>(StringComparer.Ordinal);
        var patients = new List<Patient>(count);
        while (patients.Count < count)
        {
            var nationalId = NationalId(faker.Random);
            if (!used.Add(nationalId))
            {
                continue;
            }

            var first = faker.Name.FirstName();
            var surname = faker.PickRandom(TurkishSurnames);
            var n = patients.Count;
            patients.Add(new Patient
            {
                Id = new Guid(faker.Random.Bytes(16)),
                NationalId = nationalId,
                FullName = $"{first} {surname}",
                Surname = surname,
                Email = n % 10 == 9 ? null : $"{Ascii(first)}.{Ascii(surname)}{n.ToString(CultureInfo.InvariantCulture)}@example.test",
                Phone = n % 7 == 6 ? null : $"+90 5{faker.Random.Number(30, 59)} {faker.Random.Number(100, 999)} {faker.Random.Number(10, 99)} {faker.Random.Number(10, 99)}",
                BirthYear = faker.Random.Number(1940, 2015),
                CreatedAt = createdAt,
            });
        }

        return patients;
    }

    /// <summary>11 digits, first non-zero, digit 10 and 11 per the published T.C. Kimlik No checksum rules.</summary>
    public static string NationalId(Randomizer random)
    {
        ArgumentNullException.ThrowIfNull(random);
        var d = new int[11];
        d[0] = random.Number(1, 9);
        for (var i = 1; i < 9; i++)
        {
            d[i] = random.Number(0, 9);
        }

        var odd = d[0] + d[2] + d[4] + d[6] + d[8];
        var even = d[1] + d[3] + d[5] + d[7];
        d[9] = (((odd * 7) - even) % 10 + 10) % 10;
        d[10] = d.Take(10).Sum() % 10;
        return string.Concat(d);
    }

    public static bool IsValidNationalId(string value)
    {
        if (value.Length != 11 || !value.All(char.IsAsciiDigit) || value[0] == '0')
        {
            return false;
        }

        var d = value.Select(c => c - '0').ToArray();
        var odd = d[0] + d[2] + d[4] + d[6] + d[8];
        var even = d[1] + d[3] + d[5] + d[7];
        return d[9] == (((odd * 7) - even) % 10 + 10) % 10 && d[10] == d.Take(10).Sum() % 10;
    }

    private static string Ascii(string value) => string.Concat(value.ToLowerInvariant().Select(c => c switch
    {
        'ç' => 'c',
        'ğ' => 'g',
        'ı' => 'i',
        'i' => 'i',
        'ö' => 'o',
        'ş' => 's',
        'ü' => 'u',
        'â' => 'a',
        'î' => 'i',
        'û' => 'u',
        _ => char.IsAsciiLetterOrDigit(c) ? c : '_',
    })).Replace("i̇", "i", StringComparison.Ordinal);
}
