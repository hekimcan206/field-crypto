# Threat model

Scope: field-level encryption of personal data in a PostgreSQL-backed .NET application with FieldCrypto, keys in OCI
Vault (production) or the development KMS. All data in this repository is synthetic.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Plaintext field values (national id, name, e-mail, phone, clinical notes) | application memory only | the personal data itself |
| Field ciphertexts | `bytea` columns, backups, replicas | protected data at rest |
| Blind index values | `bigint` columns | partial information about plaintexts (equality, frequency) |
| Wrapped data keys | `field_crypto_data_keys` | useless without the KMS; losing them destroys data |
| Unwrapped data keys, blind index root key | key ring cache in application memory | decrypt everything they cover |
| KEK (OCI Vault master key) | the vault, never exported | root of everything |
| OCI API signing key | application secret store | lets its holder call the KMS |

## Actors

- **A1 Database reader**: DBA, read-only analyst, anyone with a dump, backup or replica.
- **A2 Database writer**: DBA or attacker with write access, but no application or KMS credentials.
- **A3 Compromised application host**: code execution in the application process.
- **A4 Network attacker** between the application and the KMS.
- **A5 KMS operator or attacker on the KMS side.**

## Threats and mitigations (STRIDE)

| # | Threat | Actor | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | **Information disclosure**: read personal data from tables, dumps or backups | A1 | AES-256-GCM per value; keys never in the database in usable form; the demo searches every encrypted column for 200 known plaintexts and finds 0 | Value length (+45 bytes) and presence (NULL) are visible; pad values whose length is sensitive |
| T2 | **Tampering**: alter a ciphertext | A2 | GCM tag; property test flips every bit position and every flip is detected | Deleting a value or a whole row is not detected (no row-set integrity) |
| T3 | **Tampering / spoofing**: copy a valid ciphertext to another column or row (show patient A's diagnosis on patient B) | A2 | Context (table, column, row key) is GCM associated data; column copies fail everywhere; row copies fail for row-bound columns (Dapper) | EF Core columns are column-bound only (ADR 0006): a same-column row copy decrypts. Use row-bound writes for columns where this matters |
| T4 | **Tampering**: replace a wrapped data key, or point a ciphertext's header at another key | A2 | Wraps are bound to data key id and purpose (KMS associated data); the header is part of the GCM AAD; both tested | Result is denial of service (data unreadable), never a wrong plaintext |
| T5 | **Information disclosure**: learn from blind indexes (equality, frequency, dictionary attacks on low-entropy values) | A1 | Truncated HMAC under per-column keys; planner keeps >= 2 rows per average bucket; no cross-table joins (HKDF per column) | Rows alone in their bucket remain linkable (22 % at 16 bits / 100,000 rows, measured); low-entropy columns (surnames) leak coarse frequencies. Index only what must be searched |
| T6 | **Information disclosure**: read keys from application memory (heap dump, debugger, core file) | A3 | Keys zeroed on dispose; data key budget and age bound how much one key covers; retirement plus re-encryption after an incident | A process that can decrypt can be made to decrypt. Field encryption protects data at rest and from database-side actors, not from a compromised application |
| T7 | **Spoofing**: call the KMS as the application | A4/A3 | OCI request signatures (RSA-SHA256 over method, path, host, date, body hash); DevKms rejects unsigned, tampered, stale (> 5 min) and unknown-key requests; TLS to OCI | A stolen API key works until revoked; keep it in a secret store and scope the OCI policy to `use keys` on one key |
| T8 | **Repudiation**: decryptions are not attributable | A3 | OCI Vault audits every crypto call; one unwrap per data key per process makes those audit events meaningful (the cache prevents a flood) | Per-value reads are not audited by the KMS; add application-level audit where required |
| T9 | **Denial of service**: KMS outage or throttling | — | Unwrapped data keys cached; a running process keeps working for every key it has seen; one KMS call per new data key | A cold start during a KMS outage cannot decrypt |
| T10 | **Denial of service**: delete key rows, destroy a KEK version | A2/A5 | Application role has no DELETE on the key table; KEK versions must stay until rewrap has moved every key off them (runbook) | Deleting a key row crypto-shreds its values; back up the key table with the data |
| T11 | **Elevation**: SQL injection through table or column names in rotation jobs | — | Identifiers validated (`^[a-z_][a-z0-9_]*` with optional schema) and quoted; values are always parameters | — |
| T12 | **Nonce reuse** under one data key | — | Random 96-bit nonces with a budget of 10^6 per key (collision ~2^-57 per key); budget enforced under concurrency (tested) | Relies on the OS CSPRNG |

## Not covered

- Key-committing encryption: GCM is not key-committing; it would matter if an attacker could make the KMS accept a
  crafted wrapped key, which T4's binding prevents.
- Access control inside the application (who may decrypt which field). FieldCrypto encrypts; authorisation is the
  application's job.
- Plaintext in logs, caches, search engines or analytics exports outside the database.

## KVKK note

Under KVKK (Turkey's Personal Data Protection Law, Law No. 6698), encryption of personal data at rest is one of the
technical measures the data controller is expected to take. Field-level encryption with keys outside the database narrows
who can see personal data in practice. It does not replace access control, retention or deletion duties. Deleting a data
key makes every value under it unreadable (crypto-shredding); the per-process shared data keys in this design are not per
person, so crypto-shredding here works per key, not per data subject.
