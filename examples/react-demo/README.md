# KEM-DEM React Demo

A sample React application demonstrating the `kem-dem-wasm` library for hybrid encryption in the browser.

## Features

- **Generate X25519 keypairs** — public/secret key pair generation
- **Flexible field encryption** — encrypt any number of fields independently
- **HPKE-based encryption** — each field is sealed under one HPKE session with per-field AAD
- **ZK-friendly encryption** — BabyJubJub KEM-DEM over BN254 Fr field elements for ZK circuit integration
- **Encrypt / Decrypt roundtrip** — full KEM-DEM workflow visualization for both HPKE and ZK modes
- **Serialized JSON view** — inspect the encrypted package structure

## Getting Started

### Prerequisites

- Node.js 18+
- The WASM package must be built first:

```bash
cd ../..
wasm-pack build --target web --out-dir pkg
```

### Install & Run

```bash
cd examples/react-demo
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

### Build for Production

```bash
npm run build
```

## How It Works

### HPKE Mode (Standard)

1. **Generate Keypair** — Creates an X25519 keypair. The public key is shared; the secret key stays private.
2. **Add Fields** — Enter any number of field name/value pairs (e.g., SSN, DOB, salary).
3. **Encrypt** — All fields are sealed under a single HPKE session. Each field name is authenticated as AAD, preventing cross-field replay.
4. **Decrypt** — Uses the secret key to set up the HPKE receiver context, then opens each field in deterministic order.

### ZK Mode (BabyJubJub)

1. **Auto-generate Keypair** — A random BabyJubJub keypair is generated on app load. The uncompressed public key (X, Y) is displayed.
2. **Add Fields** — Same as HPKE mode. Text values are encoded to Fr field elements.
3. **Encrypt** — Each field is encoded as a Fr element and encrypted via BabyJubJub KEM-DEM. The ciphertext is a flat hex string of 32-byte elements.
4. **Decrypt** — Uses the auto-generated secret key to subtract the keystream and recover the original Fr elements, decoded back to text.

## Architecture

### HPKE Mode

- **KEM**: DHKEM(X25519, HKDF-SHA256) via the `hpke` crate (RFC 9180)
- **DEM**: AES-256-GCM via HPKE's built-in AEAD context
- **Field binding**: Per-field AAD (`kem-dem-wasm/v1/field:<name>`)
- **Deterministic order**: Fields are processed in sorted order (BTreeMap) for reproducibility

### ZK Mode

- **Curve**: BabyJubJub (Edwards over BN254)
- **KEM**: ElGamal-style ephemeral key exchange (`ephemeral = G * r`, `shared = pub * r`)
- **DEM**: Poseidon-derived keystream + field addition (`ciphertext = payload + keystream`)
- **Encoding**: inputs are 32-byte big-endian Fr hex; ciphertext is hex-encoded 32-byte little-endian Fr elements

## Files

- `src/App.jsx` — Root component with WASM initialization
- `src/components/SecureForm.jsx` — Main encryption/decryption UI
- `src/App.css` — Component styles
- `src/index.css` — Global styles
- `vite.config.js` — Vite config with `fs.allow` for the symlinked `pkg/` directory
