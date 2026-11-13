# 4. Truncated HMAC blind indexes with per-column keys and a Turkish case fold

- Status: accepted
- Date: 2026-11-13

## Context

Applications look patients up by national id, e-mail or surname. Randomised encryption (ADR 0002) makes SQL equality
impossible. Whatever makes equality possible also leaks something to a database reader.

## Options considered

1. **Deterministic encryption** of the column. Equal plaintexts give equal ciphertexts: every duplicate and every
   frequency is visible, and the ciphertext itself becomes the index.
2. **Full-length HMAC** of the normalised value. Same leakage as option 1 (equal values are linkable), but separable
   from the ciphertext.
3. **Truncated HMAC** (CipherSweet's approach): keep only `b` bits, so many plaintexts share each index value. The
   database returns false positives that the application removes after decryption; equal index values no longer imply
   equal plaintexts.
4. Order-revealing or homomorphic schemes. Much larger leakage (order) or cost; out of scope for equality.

## Decision

Option 3: `truncate(HMAC-SHA256(columnKey, normalize(value)), bits)`, 1 to 32 bits, stored as `bigint` with a b-tree.

- The column key is `HKDF-SHA256(rootKey, info = "field-crypto/blind-index/v1|table|column")`. The same national id in
  two tables gives unrelated index values, so tables cannot be joined on them.
- The root key is a key-store record with a fixed id, created insert-if-absent; processes starting at the same moment
  converge on one root key (tested with eight concurrent key rings on PostgreSQL). It is wrapped by the KEK like every
  data key, so rewrap covers it.
- `BlindIndexPlanner` picks the length: the fewest bits that keep expected false positives `n / 2^b` within a budget,
  and checks that an average bucket still holds at least two rows. The measured sweep on 100,000 ids matches the formula
  within sampling noise.
- Normalisers are part of the definition. `TurkishCaseFold` applies NFKC, trims and collapses whitespace, and folds all
  four Turkish i letters (I, ı, İ, i) to "i". Invariant lower-casing turns "İ" into "i" + U+0307, so "İrem" misses
  "IREM"; Turkish lower-casing turns "I" into "ı", so "IREM" typed on a non-Turkish keyboard misses "İrem". Folding both
  makes every spelling match and also equates "ısı" with "isi", which costs only an extra candidate.

## Consequences

- A lookup is one indexed SQL query plus decryption of the candidates; measured p50 within a fraction of a millisecond of
  a plaintext b-tree lookup at 10,000 rows (docs/benchmarks.md).
- At 16 bits and 100,000 rows, about 22 % of rows are alone in their bucket: for those, an equal index value is still
  strong evidence. The planner's bucket floor exists for this; columns with unique values should be planned for their
  final size, not today's.
- Frequency analysis on low-entropy columns (surnames) remains possible at coarse granularity. The threat model lists it.
- Changing bits, normaliser or root key means recomputing the index, which needs plaintext (Limitations).

## Sources

- CipherSweet blind index internals: https://ciphersweet.paragonie.com/internals/blind-index
- CipherSweet FAQ on truncation and false positives: https://ciphersweet.paragonie.com/faq
- GEICO Tech, "Searchable field-level encrypted customer PII with k-anonymity":
  https://www.geico.com/techblog/searchable-field-level-encrypted-customer-pii/
