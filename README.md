# kem-dem-wasm

A production-grade WebAssembly package for hybrid public-key encryption in React, implementing the **HPKE** standard ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)) with flexible per-field encryption.

## Overview

This library provides a React-friendly WASM binding around a standards-based HPKE implementation. It encrypts arbitrary JavaScript objects field-by-field under a single HPKE session, binding each field name as authenticated associated data (AAD) to prevent cross-field ciphertext replay.

## Architecture

| Layer | Standard | Implementation |
|---|---|---|
| **KEM** | DHKEM(X25519, HKDF-SHA256) | [`hpke`](https://crates.io/crates/hpke) crate |
| **KDF** | HKDF-SHA256 | [`hpke`](https://crates.io/crates/hpke) crate |
| **AEAD** | AES-256-GCM | [`hpke`](https://crates.io/crates/hpke) crate |
| **Field encryption** | HPKE `seal` with per-field AAD | Custom orchestration |
| **Key storage** | `zeroize` + `ZeroizeOnDrop` | Rust-side only |

The implementation uses **HPKE Base mode** (no sender authentication, no PSK). Each `encryptFields` call performs one HPKE `setup_sender` to create a single session context, then seals every field under that context in deterministic field-name order. The field name is bound as AAD, so ciphertexts cannot be replayed across fields.

## Project Structure

```
kem-dem-js/
├── Cargo.toml
├── src/
│   ├── lib.rs      # WASM bindings & React-facing API
│   ├── kem.rs      # HPKE wrapper (X25519 + AES-256-GCM + HKDF-SHA256)
│   └── error.rs    # Error types
├── pkg/            # Generated WASM package (not committed)
└── examples/
    └── react-demo/ # Sample React application
```

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- Node.js 18+ (for the example app)

### Build the WASM Package

```bash
# Build for web (browser/Vite)
wasm-pack build --target web --out-dir pkg
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

## Security Properties

1. **Standardized KEM-DEM**: Uses HPKE (RFC 9180) instead of a custom construction. The key schedule, nonce derivation, and context binding are all handled by the standard.
2. **Deterministic field order**: Fields are encrypted and decrypted in sorted `BTreeMap` order, eliminating `HashMap` iteration nondeterminism.
3. **Per-field AAD**: Each field name is authenticated as AAD (`kem-dem-wasm/v1/field:<name>`), preventing cross-field ciphertext replay.
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

## License

MIT OR Apache-2.0
