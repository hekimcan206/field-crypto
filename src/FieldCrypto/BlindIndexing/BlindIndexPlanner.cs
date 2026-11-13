namespace FieldCrypto.BlindIndexing;

/// <param name="MinBits">Fewest bits that keep expected false positives per query within the budget.</param>
/// <param name="MaxBits">Most bits that still put at least the requested number of rows in an average bucket.</param>
/// <param name="RecommendedBits">The most private choice inside the budget (<paramref name="MinBits"/>), when feasible.</param>
public readonly record struct BlindIndexPlan(int MinBits, int MaxBits, int RecommendedBits, bool IsFeasible)
{
    public override string ToString() => IsFeasible
        ? $"{RecommendedBits} bits (feasible range {MinBits}..{MaxBits})"
        : $"infeasible: the false-positive budget needs >= {MinBits} bits, the bucket floor allows <= {MaxBits}";
}

/// <summary>
/// Chooses a blind index length. The trade-off: a truncated index maps many plaintexts to each value, so equal index
/// values no longer prove equal plaintexts (less leakage), and every query returns extra candidate rows the application
/// must decrypt and discard (more work). With <c>n</c> rows and <c>b</c> bits a query for a value returns its true
/// matches plus about <c>n / 2^b</c> false positives.
/// </summary>
public static class BlindIndexPlanner
{
    public static double ExpectedFalsePositives(long rows, int bits)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(rows);
        ArgumentOutOfRangeException.ThrowIfLessThan(bits, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(bits, 32);
        return rows / Math.Pow(2, bits);
    }

    /// <param name="expectedRows">Rows the index will cover at the end of its life (plan for growth).</param>
    /// <param name="maxFalsePositivesPerQuery">Candidate rows per query the application accepts decrypting and discarding.</param>
    /// <param name="minRowsPerBucket">Average rows sharing an index value; at 2 or more, equal values stop implying equal plaintexts.</param>
    public static BlindIndexPlan Recommend(long expectedRows, double maxFalsePositivesPerQuery, double minRowsPerBucket = 2)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(expectedRows, 1);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFalsePositivesPerQuery);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(minRowsPerBucket);

        var min = Math.Clamp((int)Math.Ceiling(Math.Log2(expectedRows / maxFalsePositivesPerQuery)), 1, 32);
        var max = Math.Clamp((int)Math.Floor(Math.Log2(expectedRows / minRowsPerBucket)), 1, 32);
        var feasible = min <= max;
        return new BlindIndexPlan(min, max, feasible ? min : max, feasible);
    }
}
