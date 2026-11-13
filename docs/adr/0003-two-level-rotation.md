# 3. Two levels of rotation: rewrap for the KEK, online re-encryption for data keys

- Status: accepted
- Date: 2026-11-13

## Context

"Key rotation" covers two different events:

- **Scheduled KEK rotation** (OCI Vault creates a new key version; policies often require it yearly). The data keys
  are not exposed; only the key that wraps them changes.
- **Data key retirement**: a data key may have been exposed (a heap dump, a compromised host), or policy limits its age.
  Every value encrypted with it must move to a new key.

## Options considered

1. **Re-encrypt every row on every rotation.** One mechanism; cost is O(rows) even when only the KEK changed, and a
   large table rotates for hours.
2. **Rewrap only.** Cheap; does nothing when a data key itself is the problem.
3. **Both, each for its event.**

## Decision

Option 3.

- `KeyRing.RewrapAsync` unwraps each data key with whichever KEK version (or previous KMS) wrapped it and wraps it with
  the current version, then writes it back with compare-and-set on the old KEK id and version, so two concurrent jobs
  never overwrite each other. No data row is read or written. The same path migrates keys between KMSs (for example
  local development KEK to OCI Vault) through `PreviousKeyEncryptionServices`.
- `ColumnReencryptor` finds rows whose ciphertext header names a retired data key in SQL
  (`substring(col from 2 for 16) = ANY(@ids)`), so nothing is decrypted unless it must be; re-encrypts them with the
  active key in keyset-paginated batches, and writes each batch with one `UPDATE ... FROM unnest(...)` guarded by
  `IS NOT DISTINCT FROM` on every old ciphertext. A row the application changed in between is skipped and counted as a
  conflict: its new value is already on the active key.

## Consequences

- Measured (docs/benchmarks.md): rewrapping 1,000 data keys over the OCI API takes about 2.5 s on this machine; the
  10,000-patient dataset has 2 keys and rewraps in milliseconds, with an unchanged data fingerprint. Re-encryption runs at
  thousands of rows per second with five columns per row.
- An integration test runs the job while the application keeps updating rows: every last application write survives,
  and no row is left on a retired key after a second pass.
- Retirement is per process: another process keeps encrypting with its own active key until that key rolls over, and a
  later job pass picks those rows up. The runbook (docs/key-rotation.md) says so.
- Blind index key rotation is not automated: it needs a second index column and a dual-read period (Limitations).
