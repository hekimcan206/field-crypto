# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-13

### Added

- Envelope encryption for single field values: AES-256-GCM with random nonces under 256-bit data keys; a versioned
  45-byte-overhead format whose header names the data key and is authenticated together with the table, column and
  (optionally) row key.
- `KeyRing`: generates data keys, wraps them with a pluggable KMS, stores them in a key table, caches unwrapped keys,
  enforces a per-key message budget (default 1,000,000, at most 2^32) and maximum age, with truly synchronous and
  asynchronous paths.
- KMS implementations: `LocalKeyEncryptionService` (development, versioned, optional key file) and
  `OciVaultKeyEncryptionService` (OCI Vault crypto and key-version API with OCI API-key request signing, no OCI SDK).
- KEK rotation by rewrap (no data rows touched), including migration between KMSs; data key retirement with an online,
  batched, compare-and-set re-encryption job (`ColumnReencryptor`).
- Blind indexes: truncated HMAC-SHA256 under per-column HKDF keys, a converging blind index root key, Turkish case fold,
  e-mail and digit normalisers, and `BlindIndexPlanner`.
- EF Core integration: `IsEncrypted`, `HasBlindIndex`, `BlindIndexInterceptor`, `WhereBlindIndexMatchesAsync` with
  false-positive filtering.
- Dapper integration: row-bound `AddEncrypted` and `AddBlindIndex` parameters; `PostgresDataKeyStore`.
- `FieldCrypto.DevKms`: development KMS serving the OCI Vault API subset with OCI signature verification and a
  generated client key, so `docker compose up` needs no manual setup.
- `docker compose up` demo on synthetic patients: database reader view, blind index search, tampering, KEK rotation and
  data key re-encryption, each step self-checking.
- Tests: unit, FsCheck properties, golden format vectors checked against the written specification, OCI signing checked
  against the documented example, OCI adapter over HTTP, and Testcontainers PostgreSQL integration tests.
- Benchmarks (BenchmarkDotNet and an end-to-end harness), ADRs, threat model, format specification, rotation runbook, CI
  with vulnerability audit, package consumption, container and compose-demo jobs, and CodeQL.

[Unreleased]: https://github.com/hekimcan206/field-crypto/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/hekimcan206/field-crypto/releases/tag/v1.0.0
