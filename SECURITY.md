# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting instead:
**Security → Report a vulnerability** on this repository. You can expect an acknowledgement within 5 working days. If
the report is confirmed, a fix or mitigation plan follows within 30 days.

Please include the affected version or commit, steps to reproduce and the impact you observed. Reports of a ciphertext
that decrypts in a context it was not written for, a nonce or key reuse path, or a signature the development KMS accepts
when it should not are especially welcome.

## Security-relevant design

See [docs/threat-model.md](docs/threat-model.md) for assets, actors, threats and mitigations. In short:

| Area | Default |
|---|---|
| Field encryption | AES-256-GCM, random 96-bit nonce, 16-byte tag; header and table/column (and row key when known) authenticated as associated data |
| Data keys | 256-bit, generated with the OS CSPRNG, wrapped by the KMS with their id and purpose as associated data; at most 1,000,000 encryptions or 24 h each |
| KEK | OCI Vault master encryption key (never leaves the vault); the local and development KMS are for development only |
| KMS authentication | OCI API key request signatures (rsa-sha256 over method, path, host, date, body hash and length) |
| Blind indexes | truncated HMAC-SHA256 under per-column HKDF keys; bit length chosen with the planner |
| Database access | application role needs SELECT/INSERT/UPDATE on the key table, never DELETE; SQL identifiers validated and quoted |
| Secrets | None in the repository. `.env.example` holds development-only values; the development KMS generates its client key at start-up |
