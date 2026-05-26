# kem-dem-wasm

A production-grade WebAssembly package for hybrid public-key encryption in React, implementing:

- **HPKE** ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)) — standard hybrid encryption with per-field sealing
- **ZK-friendly KEM-DEM** — BabyJubJub-based encryption over BN254 `Fr` field elements for zero-knowledge circuit integration

## Overview

This library provides React-friendly WASM bindings for two complementary encryption systems:

1. **HPKE mode** — encrypts arbitrary JavaScript objects field-by-field under a single HPKE session, binding each field name as authenticated associated data (AAD) to prevent cross-field ciphertext replay.
2. **ZK mode** — encrypts payloads of BN254 scalar field (`Fr`) elements using a BabyJubJub KEM-DEM construction, producing ciphertexts that can be efficiently processed inside SNARK/STARK circuits.

## Architecture

| Layer | Standard | Implementation |
|---|---|---|
| **KEM** | DHKEM(X25519, HKDF-SHA256) | [`hpke`](https://crates.io/crates/hpke) crate |
| **KDF** | HKDF-SHA256 | [`hpke`](https://crates.io/crates/hpke) crate |
| **AEAD** | AES-256-GCM | [`hpke`](https://crates.io/crates/hpke) crate |
| **Field encryption** | HPKE `seal` with per-field AAD | Custom orchestration |
| **Key storage** | `zeroize` + `ZeroizeOnDrop` | Rust-side only |

The implementation uses **HPKE Base mode** (no sender authentication, no PSK). Each `encryptFields` call performs one HPKE `setup_sender` to create a single session context, then seals every field under that context in deterministic field-name order. The field name is bound as AAD, so ciphertexts cannot be replayed across fields.

## Installation

```bash
npm install kem-dem-wasm
```

*(Optional)* If you wish to build the package from source:

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

### Build the WASM Package

```bash
# Build for web (browser/Vite)
wasm-pack build --target web --out-dir pkg

# Build for Node.js (scripts / Circom input generation)
wasm-pack build --target nodejs --out-dir pkg-node
```

### Run Tests

```bash
# Native unit tests
cargo test --lib

# WASM integration tests (requires Chrome)
wasm-pack test --headless --chrome
```

## React API

### Initialize

```javascript
import init, { KemDem } from 'kem-dem-wasm'

await init()
const kemDem = new KemDem()
```

### Generate Keypair

```javascript
const kp = kemDem.generateKeypair()
// kp.publicKey  → Uint8Array (32 bytes)
// kp.secretKey  → Uint8Array (32 bytes)
```

### Encrypt Fields

```javascript
const pkg = kemDem.encryptFields(kp.publicKey, {
  ssn: '123-45-6789',
  dob: '1990-01-01',
  salary: '150000',
})

// pkg.kemCiphertext   → Uint8Array (HPKE encapsulated key)
// pkg.getField('ssn') → Uint8Array (encrypted field ciphertext)
// pkg.fieldNames()    → Array<string>
```

### Decrypt Fields

```javascript
const plain = kemDem.decryptFields(kp.secretKey, pkg)
// plain → { ssn: '123-45-6789', dob: '1990-01-01', salary: '150000' }
```

### Low-Level Single-Blob API

```javascript
// Encrypt a single blob
const blob = kemDem.encrypt(kp.publicKey, new TextEncoder().encode('secret data'))

// Decrypt a single blob
const decrypted = kemDem.decrypt(kp.secretKey, blob)
```

### Ethereum Wallet Integration

Derive a deterministic X25519 encryption keypair from an Ethereum wallet seed phrase, so users don't need to manage a separate encryption key.

#### Option A: BIP-32 Derivation (software wallets with seed access)

```javascript
import { HDNodeWallet, getBytes } from 'ethers'

// The library exposes the canonical BIP-44 path for encryption keys
const path = KemDem.encryptionDerivationPath()  // "m/44'/60'/0'/2147483647'/0"

// Derive the child private key directly at the encryption path
const node = HDNodeWallet.fromPhrase(mnemonic, "", path)
const ikm  = getBytes(node.privateKey)           // 32 bytes
const addr = getBytes(signerAddress)             // 20 bytes

const kp = kemDem.deriveKeypairFromIkm(ikm, addr)
// kp.publicKey  → Uint8Array (32 bytes, publish on-chain)
// kp.secretKey  → Uint8Array (32 bytes, keep local)
```

#### Option B: Sign-to-Derive (MetaMask / EIP-1193 wallets)

```javascript
// One-time signature prompt (EIP-712 typed data when available; falls back to personal_sign)
const chainId = Number(BigInt(await provider.request({ method: 'eth_chainId' })))
const path = KemDem.encryptionDerivationPath()
// NOTE: this typed-data payload is *only* used to derive a local
// encryption key via `deriveKeypairFromSignature`. There is no
// on-chain verifier, so the EIP-712 domain intentionally omits
// `verifyingContract`. Do NOT copy this snippet for the
// X25519KeyRegistry's `registerFor` path — that signature uses the
// registry's own EIP-712 domain (which DOES include
// `verifyingContract`) defined inside the contract.
const typedData = {
  types: {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' },
    ],
    KemDemDerive: [
      { name: 'action', type: 'string' },
      { name: 'path', type: 'string' },
    ],
  },
  primaryType: 'KemDemDerive',
  domain: { name: 'kem-dem-wasm', version: '1', chainId },
  message: { action: 'derive-encryption-key', path },
}
let sigHex
try {
  sigHex = await provider.request({
    method: 'eth_signTypedData_v4',
    params: [signerAddress, JSON.stringify(typedData)],
  })
} catch {
  sigHex = await provider.request({
    method: 'personal_sign',
    params: ['kem-dem-wasm/v1/derive-encryption-key', signerAddress],
  })
}
const sig  = getBytes(sigHex)                    // 65 bytes
const addr = getBytes(signerAddress)             // 20 bytes

const kp = kemDem.deriveKeypairFromSignature(sig, addr)
```

> **Security note**: The derived secret key is exposed to the JS garbage collector once returned to the browser. Never persist it in cleartext — cache in memory for the session only, or encrypt at rest with a user passphrase.

> **Hardware wallet note**: Hardware wallets (Ledger, Trezor) cannot natively derive X25519 keys. Use Option B (sign-to-derive) for hardware wallet users. The encryption secret key will live in software on the host.

#### Signer Determinism Self-Check

Before using a wallet for sign-to-derive, verify that it signs deterministically (RFC 6979). A non-deterministic signer produces a different key every time, which would lock the user out of past ciphertexts.

```javascript
// Prompt the wallet twice for the same derivation message
const sigA = await provider.request({
  method: 'personal_sign',
  params: ['kem-dem-wasm/v1/derive-encryption-key', signerAddress],
})
const sigB = await provider.request({
  method: 'personal_sign',
  params: ['kem-dem-wasm/v1/derive-encryption-key', signerAddress],
})

// Throws if the signer is non-deterministic
KemDem.verifySignerIsDeterministic(
  getBytes(sigA),
  getBytes(sigB),
)
```

### On-chain Key Registry

Once a user has derived their X25519 public key, they need a way to **publish it** so that other parties can encrypt to them just from their EVM address. The repo ships a minimal Solidity registry at [`contracts/X25519KeyRegistry.sol`](contracts/X25519KeyRegistry.sol).

**Design**:

* `bytes32 pubkey` per `(account, version)` — X25519 keys are exactly 32 B and pack into one storage slot.
* `register(uint32 version, bytes32 pubkey)` — EOA self-registration (`msg.sender == account`).
* `registerFor(account, version, pubkey, deadline, sig)` — EIP-712 typed-data path for contract / 4337 / meta-tx accounts. Per-account `registrationNonce` makes every signature single-use (replay-after-revoke is blocked).
* `revoke(version)` — marks a version permanently dead. Cannot be re-registered — caller must use a fresh version number to rotate.
* `getLatest(account)` / `get(account, version)` / `isRegistered(account, version)` — sender-side lookups.
* ECDSA path enforces low-s (EIP-2) and rejects `address(0)`. ERC-1271 path supported automatically for contract accounts.

**Sender flow**:

```javascript
import { Contract, getBytes, hexlify } from 'ethers'

const registry = new Contract(REGISTRY_ADDR, REGISTRY_ABI, provider)
const record   = await registry.getLatest(recipientAddress)
const pubKey   = getBytes(record.pubkey)              // 32 B X25519 pubkey

const pkg = kemDem.encryptFields(pubKey, { ssn: '...' })
// post pkg anywhere (IPFS, calldata, off-chain DB)
```

**Recipient publish flow** (EOA):

```javascript
const kp = kemDem.deriveKeypairFromIkm(ikm, addr)
const pubkeyHex = hexlify(kp.publicKey)               // 32 B → bytes32

const registry = new Contract(REGISTRY_ADDR, REGISTRY_ABI, signer)
await registry.register(1, pubkeyHex)                 // version 1
```

To rotate, derive a v2 keypair (e.g. via a `v2` info string) and call `registry.register(2, newPubkeyHex)`. Senders calling `getLatest` automatically pick up the new version.

> **Deployment**: the contract is non-upgradeable on purpose. New derivation schemes get a new contract address; the `SCHEMA` constant (`keccak256("kem-dem-wasm/v1/x25519-pubkey")`) makes the wire format self-describing.

## Security Properties

1. **Standardized KEM-DEM**: Uses HPKE (RFC 9180) instead of a custom construction. The key schedule, nonce derivation, and context binding are all handled by the standard.
2. **Deterministic field order**: Fields are encrypted and decrypted in sorted `BTreeMap` order, eliminating `HashMap` iteration nondeterminism.
3. **Per-field AAD with manifest binding (v2)**: Each field name is authenticated as AAD (`kem-dem-wasm/v2/field:<name>\x00<manifest>`), and the sorted field-name set is bound into a manifest hash that is mixed into every field's AAD. This prevents cross-field ciphertext replay, silent field drops, field additions, and field renames. v1 ciphertexts are intentionally not decryptable by v2.
4. **Memory safety**: Secret keys use `zeroize` in Rust, though they are still exposed to JS GC once returned to the browser.

## Example App

A complete React demo is included in `examples/react-demo/`:

```bash
cd examples/react-demo
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

> **Note**: Because the WASM package is symlinked from `../../pkg`, Vite's file-system allow list must include the parent directory. See `vite.config.js` for the configuration.

## Build for Production

```bash
cd examples/react-demo
npm run build
```

## On-Chain Key Registry

The `contracts/X25519KeyRegistry.sol` contract stores X25519 public keys on-chain, indexed by `(account, version)`. It supports two registration paths:

### Self-Registration (EOAs)

```solidity
registry.register(1, pubkeyBytes32);
```

`msg.sender` is the authenticator — no signature needed.

### Delegated Registration (Contract Accounts / 4337 / Meta-Tx)

```solidity
// Relayer submits on behalf of `account`
registry.registerFor(account, version, pubkey, deadline, eip712Signature);
```

The signature is an EIP-712 typed-data signature over:
```
Register(address account, uint32 version, bytes32 pubkey, uint256 nonce, uint256 deadline)
```

Key security properties:
- **Per-account nonce** prevents replay (including replay-after-revoke)
- **EIP-712 typed data** — wallets display the fields before signing
- **Low-s enforcement** (EIP-2) on ECDSA signatures
- **ERC-1271** support for contract account signatures
- **Fork-safe domain separator** — recomputed if `chainid` changes

### Key Revocation

```solidity
registry.revoke(version);  // Only msg.sender can revoke their own keys
```

Revoked version slots are permanently dead — the account must register with a fresh version number.

> **`getLatest` semantics after revocation:** `revoke` does **not** roll `latestVersion` back. If the latest version of an account is revoked and no higher version has been registered, `getLatest` reverts with `LatestRevoked(uint32 latestVersion)`. Sender clients **must** catch this error and surface a "key was revoked, please re-register" message rather than treating the account as never having registered (which `UnknownVersion` would imply). This is deliberate — silently scanning backwards for an older active version would defeat the purpose of revocation.

### Lookups

```solidity
// Latest active key
Record memory r = registry.getLatest(account);

// Specific version (may be revoked or empty)
Record memory r = registry.get(account, version);

// Cheap presence check
bool active = registry.isRegistered(account, version);
```

## ZK-Friendly Encryption (BabyJubJub KEM-DEM)

In addition to the HPKE/X25519 API, the library provides a **ZK-friendly encryptor** built on the BabyJubJub curve over BN254. This is designed for encrypting payloads that will later be processed inside ZK circuits (e.g., SNARKs/STARKs), where operations over the BN254 scalar field `Fr` are native.

### Architecture

| Layer | Primitive | Purpose |
|---|---|---|
| **Curve** | BabyJubJub (Edwards over BN254) | ZK-native: point ops are cheap in-circuit |
| **KEM** | ElGamal-style ephemeral key exchange | `ephemeral = G * r`, `shared = receiver_pub * r` |
| **DEM** | Poseidon-derived keystream + field addition | Each payload element: `ciphertext[i] = payload[i] + keystream[i]` |
| **Encoding** | Inputs are 32-byte big-endian Fr hex; ciphertext is hex-encoded 32-byte little-endian Fr elements | Matches the Rust/Circom wire format |

The ciphertext format is:
```
[ct_0][ct_1]...[ct_n][ephemeral_x][ephemeral_y]
```
Each element is 32 bytes. The last two elements are the uncompressed ephemeral public key, allowing the receiver to recompute the shared secret and subtract the keystream.

### API

```javascript
import init, { ZkEncryptor } from 'kem-dem-wasm'

await init()

// Generate a random BabyJubJub keypair
const kp = ZkEncryptor.generateKeypair()
// kp.secretKey        → "0x..."  (64 hex chars)
// kp.publicKey.x      → "0x..."  (64 hex chars, BabyJubJub X coordinate)
// kp.publicKey.y      → "0x..."  (64 hex chars, BabyJubJub Y coordinate)

// Encrypt a payload of Fr field elements (array of 0x-prefixed 64-char hex strings)
const payload = [
  '0x0000000000000000000000000000000000000000000000000000000000000001',
  '0x0000000000000000000000000000000000000000000000000000000000000002',
]

// ── Authenticated (recommended for anything outside a SNARK that
//    itself enforces integrity). Includes a Poseidon MAC tag.
const ctAuth = ZkEncryptor.encryptAuthenticated(
  kp.publicKey.x, kp.publicKey.y, payload,
)
// ctAuth → hex string, length = (payload.length + 3) * 64

const ptAuth = ZkEncryptor.decryptAuthenticated(kp.secretKey, ctAuth)
// ptAuth → ["0x...", "0x..."]  (throws if the MAC tag does not verify)

// ── Confidentiality-only (use only when an enclosing SNARK or
//    other channel guarantees integrity).
const ct = ZkEncryptor.encrypt(kp.publicKey.x, kp.publicKey.y, payload)
// ct → hex string, length = (payload.length + 2) * 64

const pt = ZkEncryptor.decrypt(kp.secretKey, ct)
// pt → ["0x...", "0x..."]
```

### Domain-Separated Encryption

For protocols that share the same BabyJubJub key material but require cryptographic isolation, the library supports **caller-supplied domain constants**. Domain constants provide separation between the KEM and DEM layers and — crucially — between different protocols:

```javascript
// Domain constants are 0x-prefixed 64-char hex Fr254 values.
// Convention: SHA256 hash of a descriptive protocol string, reduced mod the field.
const kemDomain = '0x...'  // e.g. Fr(SHA256("MyProtocol|PurposeKEM"))
const demDomain = '0x...'  // e.g. Fr(SHA256("MyProtocol|PurposeDEM"))

// ── Unauthenticated domain-separated encrypt/decrypt
const ct = ZkEncryptor.encryptWithDomains(
  kp.publicKey.x, kp.publicKey.y, payload,
  kemDomain, demDomain,
  false,  // compress_epk: false = uncompressed [epk_x, epk_y]
)
const pt = ZkEncryptor.decryptWithDomains(
  kp.secretKey, ct, kemDomain, demDomain, false,
)

// ── Authenticated domain-separated (recommended)
const ctAuth = ZkEncryptor.encryptAuthenticatedWithDomains(
  kp.publicKey.x, kp.publicKey.y, payload,
  kemDomain, demDomain,
  false,  // compress_epk
)
const ptAuth = ZkEncryptor.decryptAuthenticatedWithDomains(
  kp.secretKey, ctAuth, kemDomain, demDomain, false,
)
```

#### Compressed EPK Encoding

Set `compress_epk = true` to store the ephemeral public key in compressed form (`[epk_y, sign_flag]` instead of `[epk_x, epk_y]`). The ciphertext length is unchanged (still 2 trailing elements) but the encoding saves bandwidth in circuits that only need the y-coordinate:

```javascript
const ct = ZkEncryptor.encryptWithDomains(
  kp.publicKey.x, kp.publicKey.y, payload,
  kemDomain, demDomain,
  true,  // compressed
)
// Decompress must also use compress_epk = true
const pt = ZkEncryptor.decryptWithDomains(
  kp.secretKey, ct, kemDomain, demDomain, true,
)
```

### Use Cases

- **Private voting**: Encrypt votes as Fr elements, prove correctness in a SNARK without revealing plaintext
- **Confidential transfers**: Encrypt amounts as field elements, verify balance constraints in-circuit
- **ZK identity**: Encrypt identity attributes for selective disclosure proofs

### Security Notes

- **Prefer `encryptAuthenticated`/`decryptAuthenticated`** for any data that is not consumed inside a SNARK that itself enforces integrity. The authenticated variant appends a Poseidon MAC tag bound to the shared secret and the ephemeral public key, and the decrypt path verifies the tag in constant time before returning plaintext.
- **Domain separation** prevents cross-protocol attacks when multiple protocols share the same BabyJubJub key material. Use `encryptAuthenticatedWithDomains` with unique constants derived from `SHA256("ProtocolName|Purpose")` to isolate protocols cryptographically.
- The KEM uses a fresh random ephemeral scalar `r` per encryption. Reusing `r` leaks the payload.
- The unauthenticated `encrypt`/`decrypt` DEM is a Poseidon-derived stream cipher (addition in the field). It provides confidentiality but **no authentication**, so a bit-flip in the ciphertext flips the corresponding plaintext bit silently. Only use it when an enclosing SNARK or other channel guarantees integrity; otherwise use the authenticated variant or the HPKE API.
- The ciphertext stores the ephemeral public key uncompressed `(x, y)` by default. Use `compress_epk = true` with the domain-separated API to store a compressed encoding `[epk_y, sign_flag]` when bandwidth is a concern.

## License

MIT
