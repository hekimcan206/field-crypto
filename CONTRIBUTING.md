# Contributing

Thanks for taking the time to improve field-crypto.

## Prerequisites

- .NET SDK 10.0.400 or later (`global.json` rolls forward to the latest feature band)
- Docker (integration tests start PostgreSQL through Testcontainers; `docker compose up` runs the demo)

## Workflow

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Branch from `main` and keep each pull request to one concern.
3. Before pushing:

   ```bash
   dotnet build                       # must be warning-free: warnings are errors
   dotnet test                        # unit, property, golden, OCI adapter and Testcontainers tests (Docker running)
   dotnet format --verify-no-changes
   ```

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are required. They keep the history readable, make the
hand-written CHANGELOG easy to assemble at release time, and show which version bump a change needs:

- `feat:` new capability (minor bump)
- `fix:` bug fix (patch bump)
- `feat!:` or a `BREAKING CHANGE:` footer (major bump)
- `docs:`, `test:`, `build:`, `ci:`, `refactor:`, `perf:`, `chore:` for everything else

## Changing the ciphertext format or blind index derivation

Stored data depends on them ([docs/ciphertext-format.md](docs/ciphertext-format.md)). A change:

1. must keep decrypting version 1: the golden vectors in `tests/FieldCrypto.UnitTests/Golden/vectors.json` stay green;
2. writes a new format version byte instead of changing version 1, and updates the specification;
3. adds new vectors with `UPDATE_GOLDEN=1 dotnet test --project tests/FieldCrypto.UnitTests` and the diff is reviewed
   like code.

A change to blind index derivation, a normaliser or a definition's bits changes stored index values; it needs a
migration path (see [docs/key-rotation.md](docs/key-rotation.md)).

## Cryptography rules

- Only primitives from the .NET base class library (`AesGcm`, `HMACSHA256`, `HKDF`, `RSA`). No custom constructions
  without an ADR.
- Never log or put plaintext or key material in exception messages (a test checks the decryption error).
- New KMS adapters implement both the synchronous and asynchronous members of `IKeyEncryptionService`, the synchronous
  one without blocking on a task.

## Architecture decisions

A change to a decision recorded in `docs/adr/` needs a new ADR that supersedes the old one. Do not edit the old ADR in
place. Use the existing files as the format (MADR: context, options considered, decision, consequences).
