using FieldCrypto.BlindIndexing;
using FieldCrypto.UnitTests.Support;

namespace FieldCrypto.UnitTests;

public sealed class BlindIndexTests : IDisposable
{
    private static readonly BlindIndexDefinition Surname = new("patients", "surname", 32, TextNormalizers.TurkishCaseFold);
    private readonly TestRing _ring = new();

    public void Dispose() => _ring.Dispose();

    [Theory]
    [InlineData("Işık", "IŞIK")]
    [InlineData("İrem", "IREM")] // typed on a non-Turkish keyboard
    [InlineData("Irmak", "ırmak")]
    [InlineData("Işık", "işık")]
    [InlineData("İZMİR", "izmir")]
    [InlineData("İzmir", "IZMIR")]
    [InlineData("i̇zmir", "İzmir")] // decomposed dotted capital I, as some keyboards and OCR produce it
    [InlineData("  Ayşe   Nur ", "AYŞE NUR")]
    [InlineData("ﬁliz", "FILIZ")] // NFKC expands the "ﬁ" ligature
    public void Turkish_case_fold_matches_what_people_type(string stored, string typed)
    {
        TextNormalizers.TurkishCaseFold(stored).Should().Be(TextNormalizers.TurkishCaseFold(typed));
        _ring.Indexer.Compute(stored, Surname).Should().Be(_ring.Indexer.Compute(typed, Surname));
    }

    [Theory]
    [InlineData("Şule", "Sule")]
    [InlineData("Öztürk", "Ozturk")]
    [InlineData("Çelik", "Celik")]
    [InlineData("Ayşe Nur", "AyşeNur")]
    public void Turkish_case_fold_keeps_distinct_letters_distinct(string a, string b)
    {
        TextNormalizers.TurkishCaseFold(a).Should().NotBe(TextNormalizers.TurkishCaseFold(b));
    }

    [Fact]
    public void Culture_lowercasing_alone_would_miss_these_matches()
    {
        var turkish = new System.Globalization.CultureInfo("tr-TR");

        // The two failure modes the fold exists for, shown with the framework's own casing.
        "İrem".ToLowerInvariant().Should().NotBe("IREM".ToLowerInvariant(), "invariant casing leaves a combining dot");
        "İrem".ToLower(turkish).Should().NotBe("IREM".ToLower(turkish), "Turkish casing maps I to dotless ı");
        TextNormalizers.TurkishCaseFold("İrem").Should().Be(TextNormalizers.TurkishCaseFold("IREM"));
    }

    [Theory]
    [InlineData(" Ayse.Yilmaz@Example.TEST ", "ayse.yilmaz@example.test")]
    [InlineData("İLKER@example.test", "ilker@example.test")]
    public void Email_normalizer(string input, string expected) => TextNormalizers.Email(input).Should().Be(expected);

    [Theory]
    [InlineData("+90 (532) 111-22-33", "905321112233")]
    [InlineData("100 000 001 46", "10000000146")]
    [InlineData("١٢٣", "123")] // Arabic-Indic digits
    public void Digits_normalizer(string input, string expected) => TextNormalizers.DigitsOnly(input).Should().Be(expected);

    [Fact]
    public void Same_value_in_two_columns_gets_unrelated_index_values()
    {
        var patients = new BlindIndexDefinition("patients", "national_id", 32, TextNormalizers.DigitsOnly);
        var staff = new BlindIndexDefinition("staff", "national_id", 32, TextNormalizers.DigitsOnly);

        _ring.Indexer.Compute("10000000146", patients).Should().NotBe(_ring.Indexer.Compute("10000000146", staff));
    }

    [Fact]
    public void Index_is_stable_across_processes_sharing_a_key_store()
    {
        var value = _ring.Indexer.Compute("Işık", Surname);
        using var restarted = _ring.Restart();

        restarted.Indexer.Compute("ışık", Surname).Should().Be(value);
    }

    [Fact]
    public void Truncation_keeps_the_leading_bits_of_the_full_index()
    {
        var full = _ring.Indexer.Compute("Işık", Surname);
        var sixteen = _ring.Indexer.Compute("Işık", new BlindIndexDefinition("patients", "surname", 16, TextNormalizers.TurkishCaseFold));

        sixteen.Should().Be(full >> 16);
    }

    [Fact]
    public void Truncated_index_spreads_values_evenly_as_the_planner_assumes()
    {
        const int bits = 10;
        const int values = 200_000;
        var definition = new BlindIndexDefinition("patients", "national_id", bits);
        var buckets = new int[1 << bits];

        for (var i = 0; i < values; i++)
        {
            buckets[_ring.Indexer.Compute(i.ToString("D11", System.Globalization.CultureInfo.InvariantCulture), definition)]++;
        }

        // Chi-squared with 1,023 degrees of freedom: mean 1,023, sd ~45. 1,250 is ~5 sd above the mean.
        var expected = values / (double)buckets.Length;
        var chiSquared = buckets.Sum(b => (b - expected) * (b - expected) / expected);
        chiSquared.Should().BeLessThan(1250);
    }

    [Fact]
    public void Matches_applies_the_index_normalizer()
    {
        BlindIndexer.Matches("Işık", "IŞIK", Surname).Should().BeTrue();
        BlindIndexer.Matches("Işık", "Isık Can", Surname).Should().BeFalse();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(33)]
    public void Bits_must_be_1_to_32(int bits)
    {
        var act = () => new BlindIndexDefinition("t", "c", bits);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData(100_000, 50, 2, 11, 15)]
    [InlineData(1_000_000, 20, 2, 16, 18)]
    [InlineData(5_000, 1, 2, 13, 11)]
    public void Planner_balances_false_positives_against_bucket_size(long rows, double fpBudget, double minPerBucket, int minBits, int maxBits)
    {
        var plan = BlindIndexPlanner.Recommend(rows, fpBudget, minPerBucket);

        plan.MinBits.Should().Be(minBits);
        plan.MaxBits.Should().Be(maxBits);
        plan.IsFeasible.Should().Be(minBits <= maxBits);
        if (plan.IsFeasible)
        {
            plan.RecommendedBits.Should().Be(minBits);
            BlindIndexPlanner.ExpectedFalsePositives(rows, plan.RecommendedBits).Should().BeLessThanOrEqualTo(fpBudget);
        }
    }
}
