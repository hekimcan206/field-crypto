using FieldCrypto.BlindIndexing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace FieldCrypto.EntityFrameworkCore;

/// <summary>
/// Recomputes blind index columns from their (plaintext, in memory) source properties just before SaveChanges, so an
/// index can never drift from the value it indexes.
/// </summary>
public sealed class BlindIndexInterceptor(BlindIndexer indexer) : SaveChangesInterceptor
{
    private readonly BlindIndexer _indexer = indexer ?? throw new ArgumentNullException(nameof(indexer));

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        ArgumentNullException.ThrowIfNull(eventData);
        Apply(eventData.Context);
        return result;
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(eventData);
        Apply(eventData.Context);
        return ValueTask.FromResult(result);
    }

    private void Apply(DbContext? context)
    {
        if (context is null)
        {
            return;
        }

        foreach (var entry in context.ChangeTracker.Entries())
        {
            if (entry.State is not (EntityState.Added or EntityState.Modified))
            {
                continue;
            }

            foreach (var property in entry.Metadata.GetProperties())
            {
                if (property.FindAnnotation(FieldCryptoModelExtensions.BlindIndexAnnotation)?.Value is not BlindIndexBinding binding)
                {
                    continue;
                }

                var source = entry.Property(binding.SourceProperty);
                if (entry.State == EntityState.Modified && !source.IsModified)
                {
                    continue;
                }

                entry.Property(property.Name).CurrentValue = source.CurrentValue is string plaintext
                    ? _indexer.Compute(plaintext, binding.Definition)
                    : null;
            }
        }
    }
}
