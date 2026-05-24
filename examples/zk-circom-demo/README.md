# ZK Circom Demo — kem-dem-wasm

A complete end-to-end example demonstrating how `kem-dem-wasm`'s ZK-friendly BabyJubJub KEM-DEM integrates with Circom circuits.

## What This Proves

This demo shows a **private voting** use case:

1. A voter encrypts their vote (0 or 1) using `ZkEncryptor`
2. The voter generates a **ZK proof** that:
   - They know the secret key that decrypts the ciphertext
   - The decrypted vote is either 0 or 1 (valid vote)
   - Without revealing the actual vote or the secret key
3. Anyone can verify the proof using only the public ciphertext


### Components

| Component | File | Purpose |
|---|---|---|
| **Circuit** | `circuits/ZkDecryptVerifier.circom` | Verifies decryption + policy (vote ∈ {0,1}) |
| **Input Gen** | `scripts/generate-input.js` | Uses `ZkEncryptor` to create Circom witness input |
| **Public Input** | `inputs/public.json` | Ciphertext (published on-chain or shared) |
| **Private Input** | `inputs/input.json` | Secret key + payload (kept by prover) |

## Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Circom](https://docs.circom.io/getting-started/installation/) 2.0+
- [snarkjs](https://github.com/iden3/snarkjs) (`npm install -g snarkjs`)
- The `kem-dem-wasm` package built for Node.js (used by `scripts/generate-input.js`):

```bash
cd ../..
wasm-pack build --target nodejs --out-dir pkg-node
```

## Quick Start

```bash
cd examples/zk-circom-demo
npm install
npm test
```

`npm test` runs the full end-to-end pipeline (clean → compile circuit → trusted setup → generate input → prove → verify).

### 1. Generate Circuit Input

```bash
cd examples/zk-circom-demo
node scripts/generate-input.js
```

This:
- Generates a random BabyJubJub keypair
- Encrypts a vote (`1` = yes)
- Writes `inputs/input.json` (full witness) and `inputs/public.json` (public only)

### 2. Compile the Circuit

```bash
circom circuits/ZkDecryptVerifier.circom --r1cs --wasm --sym -o build/
```

### 3. Generate Trusted Setup (for demo only)

```bash
# Start a new powers of tau ceremony
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v

# Contribute randomness
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

# Prepare phase 2
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

# Generate zkey
snarkjs groth16 setup build/ZkDecryptVerifier.r1cs pot12_final.ptau build/ZkDecryptVerifier_0000.zkey

# Contribute to phase 2
snarkjs zkey contribute build/ZkDecryptVerifier_0000.zkey build/ZkDecryptVerifier_final.zkey --name="1st Contributor Name" -v

# Export verification key
snarkjs zkey export verificationkey build/ZkDecryptVerifier_final.zkey build/verification_key.json
```

### 4. Generate the Proof

```bash
# Generate witness
cd build/ZkDecryptVerifier_js
node generate_witness.js ZkDecryptVerifier.wasm ../../inputs/input.json ../../build/witness.wtns
cd ../..

# Generate proof
snarkjs groth16 prove build/ZkDecryptVerifier_final.zkey build/witness.wtns build/proof.json build/public.json
```

### 5. Verify the Proof

```bash
snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json
```

Expected output: `OK!` ✅

## How It Works

### Off-Chain (JavaScript)

```javascript
import { ZkEncryptor } from 'kem-dem-wasm'

// 1. Generate keypair
const kp = ZkEncryptor.generateKeypair()

// 2. Encrypt vote
const vote = ['0x0000000000000000000000000000000000000000000000000000000000000001']
const ciphertext = ZkEncryptor.encrypt(kp.publicKey.x, kp.publicKey.y, vote)

// 3. Submit ciphertext to blockchain / DA layer
//    The ciphertext is public — anyone can see it, but no one can decrypt without the secret key
```

The demo script `scripts/generate-input.js` loads the Node-target build from `pkg-node/` and produces a ciphertext whose wire-format is a hex string encoding 32-byte little-endian BN254 `Fr` elements.

> **Note on authentication**: The Circom circuit in this demo verifies
> confidentiality only (keystream subtraction). For production use cases
> that need integrity, use `ZkEncryptor.encryptAuthenticated` /
> `decryptAuthenticated`. The authenticated variant appends a Poseidon MAC
> tag and verifies it before decrypting. The wire format then becomes:
>
> ```
> [ct_0] [ct_1] ... [ct_n] [ephem_x] [ephem_y] [tag]
> ```
>
> Total size: `(n + 3) * 32` bytes. The MAC computation is documented in
> `docs/test-vectors.md` (Part D).

### In-Circuit (Circom)

The circuit `ZkDecryptVerifier.circom` proves:

```
Given public ciphertext = [ct_0, ct_1, ..., ct_n, ephem_x, ephem_y]:

1. The prover knows secret_key and payload[0..n]
2. For each i: ciphertext[i] == payload[i] + keystream[i]  (mod Fr)
3. For each i: payload[i] * (payload[i] - 1) == 0         (vote is 0 or 1)
```

The verifier checks the proof without learning:
- The secret key
- The actual vote value

### On-Chain (Solidity)

```solidity
// The verifier contract checks the proof
bool valid = verifier.verifyProof(a, b, c, publicInputs);
require(valid, "Invalid proof");

// publicInputs includes the ciphertext
// If valid, we know:
// - The voter knows the secret key
// - The vote is 0 or 1
// - But we don't know which!
```

## Security Notes

- **This is a demo**: The circuit is minimal and focused on proving correctness of decryption and the vote policy. A production circuit would need a full hardened BabyJubJub gadget set and careful constraints review.
- **Authentication available**: The library provides `ZkEncryptor.encryptAuthenticated` / `decryptAuthenticated` for integrity. The Circom circuit in this demo does not verify the MAC tag; it only proves confidentiality. For production, either extend the circuit to verify the Poseidon MAC or use the authenticated decrypt path off-chain before feeding the plaintext into a circuit.
- **Trusted setup**: The Groth16 trusted setup in this demo is for testing only. Production requires a multi-party computation (MPC) ceremony.

## Next Steps

- Replace the demo vote policy (`vote ∈ {0,1}`) with your application-specific policy constraints
- Replace/extend the keystream derivation gadget as needed (the demo uses circomlib-compatible Poseidon)
- Deploy the verifier contract to a testnet
- Build a React UI that generates proofs in the browser
