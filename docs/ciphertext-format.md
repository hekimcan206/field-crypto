# Ciphertext format, version 1

Every encrypted field value is one byte string:

```text
offset  size  content
     0     1  format version, 0x01
     1    16  data key id: UUID in RFC 9562 byte order (identical to PostgreSQL uuid_send)
    17    12  nonce, random per value
    29     n  AES-256-GCM ciphertext, n = UTF-8 length of the plaintext
  29+n    16  GCM tag
```

Overhead: 45 bytes. The data key is the 32-byte key stored, wrapped by the KMS, in `field_crypto_data_keys` under that id.

## Associated data

```text
AAD = bytes[0..17)                       -- the header: version and data key id
    || "fc-ctx-1"                        -- ASCII
    || be32(len(table))  || table        -- UTF-8
    || be32(len(column)) || column       -- UTF-8
    || 0x00                              -- column-bound
     | 0x01 || be32(len(rowKey)) || rowKey   -- row-bound
```

Lengths are big-endian 32-bit byte counts, so `("ab","c")` and `("a","bc")` never encode alike. Row keys are the text form
of the primary key (`bigint` and `uuid` as PostgreSQL prints them).

## Finding rows by data key in SQL

```sql
SELECT id FROM patients WHERE substring(national_id from 2 for 16) = uuid_send('0190...'::uuid);
```

## Test vectors

`tests/FieldCrypto.UnitTests/Golden/vectors.json` holds fixed-key, fixed-nonce vectors for this format and for blind
indexes. The unit tests re-derive each ciphertext vector from this document with raw AES-GCM, independent of the
library's encoder.

## Blind index values

```text
columnKey = HKDF-SHA256(ikm = rootKey, salt = empty, info = "field-crypto/blind-index/v1|" || table || "|" || column, L = 32)
value     = first 32 bits of HMAC-SHA256(columnKey, UTF-8(normalize(input))), big-endian, shifted right by (32 - bits)
```

Stored as `bigint`, range `[0, 2^bits)`.

## Wrapped data key record

| column | content |
|---|---|
| `id` | data key id (the one in ciphertext headers); the blind index root key has the fixed id `6d1f0a52-2c4e-4b3e-9f6a-0b8c1d2e3f40` |
| `purpose` | 1 data, 2 blind index root |
| `kek_id`, `kek_version` | which KEK version wrapped it (an OCI key OCID and key version OCID) |
| `wrapped_key` | KMS ciphertext; for OCI Vault the UTF-8 bytes of the base64 string the API returned |
| `created_at`, `retired_at` | retired keys decrypt but never encrypt; rows on them are re-encryption candidates |

KMS associated data for every wrap: `{"fc-data-key-id": "<uuid>", "fc-purpose": "data" | "blind-index"}`.
