# Key rotation runbook

Two different operations (ADR 0003). Pick by what happened.

| Event | Operation | Cost | Data rows touched |
|---|---|---|---|
| Scheduled KEK rotation, KMS policy | rotate the vault key, then rewrap | one unwrap + one wrap + one UPDATE per data key (~4.5 ms per key measured over the development KMS) | none |
| Moving to another KMS (local development key to OCI Vault) | configure the old KMS as previous, rewrap | same | none |
| A data key may be exposed, or exceeds its age policy | retire it, re-encrypt | thousands of rows per second (8,626 rows/s with 5 columns, measured) | every row using the key |
| A KEK version may be exposed | rotate the vault key, rewrap, then retire **all** data keys and re-encrypt | both | all |

## KEK rotation (OCI Vault)

1. Rotate the master encryption key in the vault (console "Rotate Key", or `CreateKeyVersion`;
   `OciVaultKeyEncryptionService.CreateKeyVersionAsync` does the same). New wraps use the new version at once.
2. Run `await keyRing.RewrapAsync()` from one process (a job or an admin endpoint). It reports
   `Examined / Rewrapped / AlreadyCurrent / Conflicts`; conflicts mean another rewrap changed a record first and are safe.
3. Check: `SELECT kek_version, count(*) FROM field_crypto_data_keys GROUP BY 1;` shows only the current version.
4. Only then disable or schedule deletion of the old key version. Deleting it earlier makes every data key still wrapped
   by it unreadable.

Running processes need nothing: their cached data keys do not change, and new processes unwrap with whichever version
the record names.

## Migrating KMS

```csharp
var options = new KeyRingOptions();
options.PreviousKeyEncryptionServices.Add(localDevelopmentKek); // unwrap only
using var ring = new KeyRing(ociVault, store, options);
await ring.RewrapAsync();                                        // every record now names the OCI key
```

## Data key retirement and re-encryption

1. In every running process: `await keyRing.RetireDataKeyAsync(id)` (or `RetireActiveDataKeyAsync`), or restart the
   processes after marking the key retired. A process keeps encrypting with its own active key until it notices, which
   is why step 3 runs twice.
2. Run the job per table, with the binding each column was written with:

   ```csharp
   var target = new ReencryptionTarget("patients", "id", "uuid",
       [new("national_id", RowBound: false), new("email", RowBound: false)]);
   var result = await new ColumnReencryptor(dataSource, encryptor).ReencryptRetiredAsync(target, batchSize: 1000);
   ```

   It is online: rows the application changes during the run are skipped as conflicts (their new values already use the
   active key).
3. Run it again after all processes have rolled their active keys. `RowsExamined == 0` means done.
4. Verify: no row references the retired id:
   `SELECT count(*) FROM patients WHERE substring(national_id from 2 for 16) = uuid_send('<id>'::uuid);`
5. Only after a backup cycle, delete the retired key row if it must be destroyed (crypto-shredding of anything left).

## Blind index root key

Not automated. Changing it (or a definition's bits or normaliser) means: add a second index column, write both, backfill
the new one from decrypted values, switch reads, drop the old column. Plan bits for the final table size to avoid it.
