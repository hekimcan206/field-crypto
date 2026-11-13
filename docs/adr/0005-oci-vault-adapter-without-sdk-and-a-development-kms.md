# 5. OCI Vault adapter without the OCI SDK, tested against a development KMS

- Status: accepted
- Date: 2026-11-13

## Context

Production uses OCI Vault: a master encryption key in a vault, reached through the vault's crypto endpoint
(`POST /20180608/encrypt`, `/decrypt`) and management endpoint (key versions). Requests are authenticated with OCI API
key signatures (draft-cavage HTTP signatures, rsa-sha256). There is no OCI tenancy available to this project, and
developers need a KMS on their laptop and in CI that behaves like Vault where it matters: versions, rotation, associated
data, authentication.

## Options considered

1. **OCI .NET SDK.** Official request models and signing; a large dependency tree for four calls, and its synchronous
   story (needed by EF Core converters, ADR 0006) is not a first-class path.
2. **HashiCorp Vault Transit or LocalStack KMS as the development KMS.** Real KMS semantics, but a different API from
   OCI's: the OCI adapter would stay untested, and the images are several hundred MB.
3. **A small adapter on HttpClient plus a development KMS that serves the same OCI API subset and verifies OCI
   signatures.**

## Decision

Option 3.

- `OciRequestSigningHandler` signs `date (request-target) host` for GET and adds `content-length content-type
  x-content-sha256` for POST, overriding both `Send` and `SendAsync`, so the synchronous path is real.
- The signing string builder is checked against the example published in OCI's "Request Signatures" documentation, and
  signatures are verified with the documented test public key. The documented date ("Thu, 05 Jan 2014") names the wrong
  weekday (5 January 2014 was a Sunday), so the end-to-end test adjusts only that token; the documentation gives no
  concrete signature value to compare.
- `FieldCrypto.DevKms` serves `encrypt`, `decrypt`, `GET keys/{id}` and `POST keys/{id}/keyVersions` with the same JSON
  shapes as the OCI SDK models (EncryptDataDetails, EncryptedData, DecryptDataDetails, Key, KeyVersion). It rejects
  unsigned or tampered requests (body hash, length, clock skew, unknown key) with 401, answers every decrypt rejection
  with the same 400 so it is not an oracle, and on first start writes a client API key into a shared volume and trusts
  it, which is what makes `docker compose up` zero-step.
- 400 from decrypt maps to `CryptographicException` (the key ring reports an unwrap failure); everything else maps to
  `OciVaultException` with the `opc-request-id`.

## Consequences

- The adapter has not been run against a live OCI tenancy. Field names follow the SDK models and the published API;
  differences in error bodies or headers would surface only there (Limitations).
- No retry policy is built in: KMS calls happen once per data key, and callers can add `Microsoft.Extensions.Http.Resilience`
  to the HttpClient.
- The development KMS is explicitly not a KMS: its keys live in its process (optionally a state file). It logs a warning
  at start-up.

## Sources

- OCI documentation, Request Signatures: https://docs.oracle.com/iaas/Content/API/Concepts/signingrequests.htm
- OCI SDK EncryptDataDetails model: https://rubydoc.info/gems/oci/2.14.0/OCI/KeyManagement/Models/EncryptDataDetails
- OCI Terraform `oci_kms_encrypted_data` (associated data limits):
  https://docs.oracle.com/en-us/iaas/tools/terraform-provider-oci/7.22.0/docs/r/kms_encrypted_data.html
