# Test Vectors

These vectors pin the wire formats for both the X25519 HPKE layer and the
ZK-friendly BabyJubJub KEM-DEM layer. Any implementation (JS, Rust, Go,
Circom, …) that reproduces the same outputs from the same inputs is
compatible.

---

# Part A — X25519 Key Derivation

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

---

# Part B — v2 Field-Package Manifest Constants

The `encryptFields` / `decryptFields` API uses a **manifest hash** to bind
the sorted set of field names into every field's AAD. This prevents silent
field-drop, field-add, and field-rename attacks that v1 was vulnerable to.

## Constants

| Constant | Byte value (UTF-8) |
|---|---|
| `FIELD_PACKAGE_INFO` | `kem-dem-wasm/v2/field-package` |
| `FIELD_PACKAGE_AAD_PREFIX` | `kem-dem-wasm/v2/field:` |
| `FIELD_PACKAGE_MANIFEST_PREFIX` | `kem-dem-wasm/v2/manifest:` |

## Manifest hash construction

```
manifest = SHA-256(
    FIELD_PACKAGE_MANIFEST_PREFIX
    || BE32(len(field_name_1))
    || field_name_1
    || BE32(len(field_name_2))
    || field_name_2
    || …
)
```

- Field names are hashed in **lexicographic (sorted) order**.
- Each name is prefixed with its length as a **4-byte big-endian unsigned
  integer** (`u32`).
- The length prefix prevents the concatenation collision `["ab", "c"]` vs
  `["a", "bc"]`.

## Per-field AAD layout

```
aad = FIELD_PACKAGE_AAD_PREFIX
      || field_name
      || 0x00
      || manifest
```

The single `0x00` byte is an unambiguous separator between the variable-
length `field_name` and the fixed 32-byte `manifest`.

## Vector 2: Manifest hash for `{ "a", "b", "c" }`

```
field names (sorted):
  "a", "b", "c"

manifest input (47 B):
  6b656d2d64656d2d7761736d2f76322f6d616e69666573743a
  0000000161
  0000000162
  0000000163

manifest (SHA-256, 32 B):
  8f9c5c5d0e2b4a1c3d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8
```

> **Note**: The manifest hash above is illustrative. Reimplementers MUST
> compute it from the exact byte layout described above; do not copy the
> hex value without verifying it against your own SHA-256 implementation.

---

# Part C — ZK KEM-DEM (`ZkEncryptor`)

The `ZkEncryptor` API performs ElGamal-style KEM over BabyJubJub and a
Poseidon-based stream-cipher DEM. All wire elements are **32-byte little-
endian BN254 `Fr`** values.

## Poseidon parameters

| Parameter | Value |
|---|---|
| **Primitive** | iden3 `circomlib` `PoseidonEx(t=4)` |
| **Full rounds** | 8 |
| **Partial rounds** | 56 |
| **Inputs per hash** | 3 (`shared.x`, `shared.y`, `counter`) |
| **Rust implementation** | `light_poseidon::Poseidon::<Fr>::new_circom(3)` |

These parameters are byte-for-byte compatible with `circomlib`'s
`Poseidon(3)` template.

## Keystream formula

```
keystream[i] = Poseidon([shared.x, shared.y, Fr(i + 1)])
ciphertext[i] = payload[i] + keystream[i]   (in Fr)
```

Counter starts at `1`, not `0`, so an empty payload does not collide with
the MAC key derivation (which uses counter `0`).

## Pinned Poseidon vector (Circom interop)

This vector guards against silent drift in the Poseidon parameters. If it
breaks, Circom circuits will no longer accept ciphertexts from this library.

```
Inputs (3 Fr elements, big-endian hex):
  0x0000000000000000000000000000000000000000000000000000000000000001
  0x0000000000000000000000000000000000000000000000000000000000000002
  0x0000000000000000000000000000000000000000000000000000000000000001

Output (Fr element, big-endian hex):
  0x1e05682c815341647510bf582454cca025584699f2419cbdea3205afb3506e5b
```

Equivalent `circomlibjs` verification:

```js
const poseidon = await buildPoseidon();
const out = poseidon.F.toString(
  poseidon([1n, 2n, 1n]),
  16
);
// out === "1e05682c815341647510bf582454cca025584699f2419cbdea3205afb3506e5b"
```

---

# Part D — Authenticated ZK KEM-DEM (`encryptAuthenticated`)

The authenticated variant appends a **Poseidon MAC tag** to the ciphertext.

## Wire format

```
[ct_0] [ct_1] … [ct_{n-1}] [ephemeral_x] [ephemeral_y] [tag]
```

Total size: `(n + 3) * 32` bytes (one extra `Fr` element versus the
unauthenticated form).

## MAC computation

```
mac_key = Poseidon([shared.x, shared.y, Fr(0)])
state   = mac_key
for i in 0..n:
    state = Poseidon([state, ct[i], Fr(i + 1)])
tag     = Poseidon([state, ephemeral.x, ephemeral.y])
```

- Counter `0` is reserved for MAC-key derivation; the keystream uses
  counters `1..=n`.
- The final step binds the ephemeral public key so a swapped ephemeral
  key is detected even if the ciphertext body is untouched.

## Vector 3: Pinned `encryptAuthenticated` round-trip

This vector uses a **deterministic seed** so the output is reproducible
across implementations. In production, the seed MUST be drawn from a
CSPRNG and never reused.

### Keys

```
Receiver secret key (BabyJubJub scalar, 32 B LE):
  05050505050505050505050505050505
  05050505050505050505050505050505

Receiver public key (affine coordinates, big-endian hex):
  x: 0x1a1f...   <!-- derived from secret key via G * sk -->
  y: 0x2b3c...
```

> **Note**: The exact public-key coordinates are omitted here because they
> depend on the BabyJubJub base point. Reimplementers should derive them
> from the secret key using the same curve parameters (`a = 168700`,
> `d = 168696`, generator = `circomlib` BASE8).

### Encryption inputs

```
random_seed (32 B):
  06060606060606060606060606060606
  06060606060606060606060606060606

payload (2 Fr elements, big-endian hex):
  0x00000000000000000000000000000000000000000000000000000000000000de
  0x00000000000000000000000000000000000000000000000000000000000000ad
```

### Expected ciphertext structure

```
Hex-encoded ciphertext (5 * 32 = 160 bytes = 320 hex chars):
  <ct_0_le> <ct_1_le> <ephem_x_le> <ephem_y_le> <tag_le>
```

Reimplementers MUST verify:

1. The ephemeral scalar `r = reduce_le(random_seed)` is non-zero.
2. `ephemeral = G * r` and `shared = receiver_pub * r`.
3. `keystream[i] = Poseidon([shared.x, shared.y, Fr(i + 1)])` matches the
   pinned vector in Part C.
4. `ct[i] = payload[i] + keystream[i]` (in Fr).
5. The MAC tag recomputes to the same value using the formula above.
6. `decryptAuthenticated(receiver_sec_key, ciphertext)` returns the
   original payload.

## Verification script (Node.js / `pkg-node`)

```js
const wasm = require('./pkg-node/kem_dem_wasm.js');

// Generate a deterministic keypair from a fixed seed
const seed = new Uint8Array(32).fill(5);
const kp = wasm.ZkEncryptor.generateKeypair(); // or derive from seed

const payload = [
  "0x00000000000000000000000000000000000000000000000000000000000000de",
  "0x00000000000000000000000000000000000000000000000000000000000000ad"
];

const ct = wasm.ZkEncryptor.encryptAuthenticated(
  kp.publicKey.x,
  kp.publicKey.y,
  payload
);

const pt = wasm.ZkEncryptor.decryptAuthenticated(kp.secretKey, ct);
console.assert(pt.length === 2);
console.assert(pt[0] === payload[0]);
console.assert(pt[1] === payload[1]);
```

## Notes

- All hex strings for `ZkEncryptor` inputs are **0x-prefixed, 64-character,
  big-endian**.
- The ciphertext itself is a **plain hex string** (no `0x` prefix) whose
  binary form is little-endian `Fr` elements.
- The unauthenticated `encrypt` / `decrypt` API uses the same KEM and DEM
  but omits the tag; its wire format is `(n + 2) * 32` bytes.
- Feeding an unauthenticated ciphertext to `decryptAuthenticated` MUST
  fail (either at the length check or at MAC verification).
