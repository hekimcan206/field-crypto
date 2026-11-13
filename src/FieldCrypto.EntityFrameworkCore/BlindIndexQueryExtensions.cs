using System.Linq.Expressions;
using FieldCrypto.BlindIndexing;
using Microsoft.EntityFrameworkCore;

namespace FieldCrypto.EntityFrameworkCore;

/// <param name="Matches">Rows whose decrypted value equals the query under the index's normalisation.</param>
/// <param name="Candidates">Rows the database returned for the index value (matches plus false positives).</param>
public sealed record BlindIndexResult<TEntity>(IReadOnlyList<TEntity> Matches, int Candidates)
{
    public int FalsePositives => Candidates - Matches.Count;
}

public static class BlindIndexQueryExtensions
{
    /// <summary>
    /// Equality search on an encrypted property: filter by the blind index in SQL, then decrypt the candidates (EF Core
    /// does that while materialising) and drop the false positives a truncated index returns by design.
    /// </summary>
    public static async Task<BlindIndexResult<TEntity>> WhereBlindIndexMatchesAsync<TEntity>(
        this DbSet<TEntity> set,
        BlindIndexer indexer,
        Expression<Func<TEntity, string?>> sourceProperty,
        string value,
        Func<IQueryable<TEntity>, IQueryable<TEntity>>? refine = null,
        CancellationToken cancellationToken = default)
        where TEntity : class
    {
        ArgumentNullException.ThrowIfNull(set);
        ArgumentNullException.ThrowIfNull(indexer);
        ArgumentNullException.ThrowIfNull(sourceProperty);
        ArgumentNullException.ThrowIfNull(value);
        var sourceName = sourceProperty.Body is MemberExpression member
            ? member.Member.Name
            : throw new ArgumentException("Expected a property access such as p => p.NationalId.", nameof(sourceProperty));

        var (indexName, binding) = set.EntityType.GetProperties()
            .Select(p => (p.Name, Binding: p.FindAnnotation(FieldCryptoModelExtensions.BlindIndexAnnotation)?.Value as BlindIndexBinding))
            .FirstOrDefault(p => p.Binding?.SourceProperty == sourceName);
        if (binding is null)
        {
            throw new InvalidOperationException($"{typeof(TEntity).Name}.{sourceName} has no blind index; configure one with HasBlindIndex.");
        }

        var indexValue = indexer.Compute(value, binding.Definition);
        var parameter = Expression.Parameter(typeof(TEntity), "e");
        var filter = Expression.Lambda<Func<TEntity, bool>>(
            Expression.Equal(
                Expression.Call(typeof(EF), nameof(EF.Property), [typeof(long?)], parameter, Expression.Constant(indexName)),
                // A member access on a closure object, so EF Core sends the index value as a parameter (one cached plan)
                // instead of inlining a literal per query.
                Expression.Property(Expression.Constant(new IndexValue(indexValue)), nameof(IndexValue.Value))),
            parameter);

        IQueryable<TEntity> query = set.Where(filter);
        if (refine is not null)
        {
            query = refine(query);
        }

        var candidates = await query.ToListAsync(cancellationToken);
        var read = sourceProperty.Compile();
        var matches = candidates.Where(c => read(c) is { } plaintext && BlindIndexer.Matches(plaintext, value, binding.Definition)).ToList();
        return new BlindIndexResult<TEntity>(matches, candidates.Count);
    }

    private sealed record IndexValue(long? Value);
}
