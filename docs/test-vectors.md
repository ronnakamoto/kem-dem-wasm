# Test Vectors for X25519 Key Derivation

These vectors pin the derivation wire format. Any implementation (JS, Rust,
Go, …) that produces the same `(pk, sk)` from the same `(ikm, address)` is
compatible.

## Derivation Parameters

| Parameter | Value |
|---|---|
| **KDF** | HKDF-SHA256 |
| **Salt** | `SHA-256("kem-dem-wasm/v1/x25519-derivation-salt")` |
| **Salt (hex)** | `161962a5d0a626f3f621428f82d6fdc3a83822a92be2abcd42d0901b54f94e96` |
| **Info** | `"kem-dem-wasm/v1/x25519/" \|\| hex(eth_address)` |
| **OKM length** | 32 bytes |
| **Curve** | X25519 (Curve25519) |

> **Note on the salt**: we deliberately use `SHA-256(domain_string)` rather
> than passing the raw domain string directly to HKDF, so the salt is a
> fixed 32-byte value identical to the HMAC-SHA256 block-sized constant.
> Reimplementers MUST compute the hash themselves and check it matches the
> value above before using the vectors below.

## Relation to RFC 9180 `DeriveKeyPair`

This library does **not** use HPKE's standardised
[`DeriveKeyPair`](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3)
function. Instead it performs HKDF-Extract+Expand directly on the IKM and
then constructs the X25519 secret key from the 32 raw output bytes.

The choice is intentional:

* **Per-account binding**: RFC 9180 `DeriveKeyPair` takes only the IKM
  and a suite-id. We need to bind the EVM address into the derivation
  so that the same seed deterministically produces different
  encryption keys for different EVM accounts. HKDF's `info` parameter
  is the natural place for that binding; layering RFC 9180 on top
  would either ignore the address (wrong) or hash it into the IKM
  twice (wasteful and harder to audit).
* **X25519 specificity**: every 32-byte string is a valid X25519
  scalar (RFC 7748 clamping is applied at use-time inside the
  `hpke`/`x25519-dalek` stack), so the simpler HKDF-only path is
  sound. If we later support a PQ KEM where keygen requires rejection
  sampling (e.g. Kyber), we will switch to that KEM's standardised
  `DeriveKeyPair`.

Implementers porting this scheme to another HPKE library MUST replicate
the HKDF parameters exactly — they cannot substitute `DeriveKeyPair`.

## Vector 1: Standard derivation

```
ikm (32 B):
  0102030405060708090a0b0c0d0e0f10
  1112131415161718191a1b1c1d1e1f20

eth_address (20 B):
  d8da6bf26964af9d7eed9e03e53415d37aa96045

info string (62 B, UTF-8):
  "kem-dem-wasm/v1/x25519/d8da6bf26964af9d7eed9e03e53415d37aa96045"

secret_key (32 B):
  e10720f42730f9b07b4e724a226f101372bb24fd4e56ab8ad31c040d3eb2003b

public_key (32 B):
  21ab02c2b9e78a8bba19dabbf1a88a69d8042163a477cec1ad74e78903a7ee78
```

## Verification

The derived `(public_key, secret_key)` pair must successfully round-trip
through HPKE Base mode:

```
encryptFields(public_key, { "test": "hello" })  →  EncryptedPackage
decryptFields(secret_key, EncryptedPackage)      →  { "test": "hello" }
```

## Notes

- The `eth_address` in the info string is **lower-case hex, no `0x` prefix**.
- The `ikm` can be a BIP-32 child private key (32 B from path
  `m/44'/60'/0'/2147483647'/0`) or `keccak256(personal_sign(...))` (32 B).
- Any 32-byte `ikm` with at least 16 bytes of entropy is accepted.
  Inputs shorter than 16 bytes are rejected.
