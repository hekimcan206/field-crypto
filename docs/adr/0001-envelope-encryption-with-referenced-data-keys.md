# 1. Envelope encryption with data keys referenced by id

- Status: accepted
- Date: 2026-11-13

## Context

Personal data in a few columns (national id, name, e-mail, phone, clinical notes) must be unreadable to anyone who
can read the database: DBAs, backups, replicas, a leaked dump. The key that protects it must live in a KMS (OCI Vault in
production) that never hands out its own key material, can rotate, and audits use.

A KMS is a network service with latency, rate limits and per-call billing. Encrypting each value with a KMS call does
not scale: the benchmark measures a loopback KMS round trip at about 1-2 ms, and a real cloud KMS is further away.

## Options considered

1. **Encrypt every value through the KMS.** Simplest; every read and write is a KMS round trip. Measured here without a
   cache (one data key per value): 1,429 KMS wraps for 300 patients and a write path an order of magnitude slower
   (docs/benchmarks.md).
2. **One static application key** in configuration. Fast; no rotation story, the key sits next to the data in every
   deployment, nothing audits its use.
3. **Envelope encryption, wrapped data key stored inline in every ciphertext** (the AWS Encryption SDK message format
   does this). Self-contained ciphertexts. Each value carries the wrapped key: an OCI Vault ciphertext of a 32-byte key is
   a base64 string of well over 100 bytes, more than ten times an 11-digit national id. A KEK rotation must rewrite every
   row.
4. **Envelope encryption, data keys in a key table, ciphertexts reference them by a 16-byte id.**

## Decision

Option 4. A `KeyRing` generates a 256-bit data key, wraps it with the KMS (associated data: key id and purpose), stores
the wrapped key in `field_crypto_data_keys`, caches the unwrapped key in memory, and uses it for up to
`MaxMessagesPerDataKey` encryptions (ADR 0002) or `MaxDataKeyAge`. A ciphertext names its data key by id in its header,
so a reader unwraps each data key once per process.

The key table holds only wrapped keys. A KEK rotation rewrites those rows and nothing else (ADR 0003).

## Consequences

- Measured: 10,000 patients (5 encrypted fields each) cost 2 KMS wraps on the write path and 1 unwrap on a cold read.
- Per-value overhead is a fixed 45 bytes (version, key id, nonce, tag), independent of the KMS.
- The key table becomes a dependency of decryption. It is small and is backed up with the database; losing a row
  crypto-shreds every value under that key, so the application role gets no DELETE on it.
- Ciphertexts are not self-contained: moving data to another system needs the key rows too.
- Unwrapped data keys live in process memory for the process lifetime, the trade-off every envelope client makes
  (threat model T6).

## Sources

- AWS Security Blog, "How AWS KMS and AWS Encryption SDK overcome symmetric encryption bounds":
  https://aws.amazon.com/blogs/security/how-aws-kms-and-aws-encryption-sdk-overcome-symmetric-encryption-bounds
- OCI Key Management, generating data encryption keys from a master encryption key:
  https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/usingkeys_topic-To_generate_a_data_encryption_key_from_your_Vault_master_encryption_key.htm
