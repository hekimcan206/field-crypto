# 2. AES-256-GCM with random nonces, a per-key message budget and context binding

- Status: accepted
- Date: 2026-11-13

## Context

Field values are short, read often and must be tamper-evident: a ciphertext that is altered, or copied from one patient
to another, must fail rather than show the wrong person's data. The algorithm must be in the .NET 10 base class library
on Linux and Windows without native add-ons.

## Options considered

1. **AES-256-GCM, random 96-bit nonce.** In the BCL, hardware accelerated, authenticated with associated data. NIST SP
   800-38D limits a key to 2^32 encryptions with random nonces (nonce-collision probability about 2^-32); a collision
   under one key breaks confidentiality and authenticity.
2. **AES-GCM-SIV** (nonce-misuse resistant). Not in the .NET BCL.
3. **XChaCha20-Poly1305** (192-bit nonces, no practical limit). Not in the BCL (ChaCha20-Poly1305 with 96-bit nonces
   is, with the same bound as GCM).
4. **Deterministic encryption** so equal values produce equal ciphertexts and can be indexed. Leaks equality of every
   value to anyone with read access; equality search is handled separately by blind indexes (ADR 0004).

## Decision

Option 1, with two additions:

- **Message budget.** The key ring rolls to a new data key after `MaxMessagesPerDataKey` encryptions (default
  1,000,000, rejected above 2^32) or `MaxDataKeyAge` (default 24 h). The counter is incremented before use, so under
  contention no more than the budget ever receives a key; a 16-thread test checks this. With 10^6 messages per key the
  collision probability per key is about 10^12 / 2^97, around 2^-57.
- **Context as associated data.** The AAD is the 17-byte header (version, data key id) followed by a length-prefixed
  encoding of table, column and, when known, the row key. A ciphertext moved to another column fails; with a row key,
  moved to another row fails. Changing the version byte or pointing the header at another data key also fails.

## Consequences

- Every encryption of the same value differs; equality queries on encrypted columns return nothing (an integration test
  shows this) and must use the blind index.
- Row binding needs the row key at write time. Dapper code has it; EF Core value converters do not (ADR 0006).
- GCM is not key-committing. A party able to forge wrapped keys could craft a ciphertext that decrypts under two keys;
  here wrapped keys come only from the KMS, and wraps are bound to their key id (threat model T4).
- The format is versioned; golden vectors in the tests pin version 1 byte for byte.

## Sources

- NIST SP 800-38D and its 2024 revision draft (random-IV limit of 2^32 invocations):
  https://csrc.nist.gov/pubs/sp/800/38/d/r1/iprd
- AWS Security Blog on symmetric encryption bounds:
  https://aws.amazon.com/blogs/security/how-aws-kms-and-aws-encryption-sdk-overcome-symmetric-encryption-bounds
- IACR ePrint 2024/1111 (critique of 96-bit random nonces in GCM): https://eprint.iacr.org/2024/1111.pdf
