// Generate Circom input from a real `kem-dem-wasm` ZkEncryptor ciphertext.
//
// Pipeline:
//   1. Pick a vote (0 or 1) and the receiver's BabyJubJub secret seed.
//   2. Use the (Node-target) WASM module to derive the keypair and
//      encrypt the vote — exactly the same code path a browser dApp
//      would use.
//   3. Parse the resulting little-endian-Fr-bytes ciphertext into the
//      Fr decimal strings the Circom circuit expects.
//   4. Emit `inputs/input.json` (full witness, private + public) and
//      `inputs/public.json` (just the public ciphertext, suitable for
//      `snarkjs groth16 verify`).
//
// The script is intentionally Node-native (no bundler). It loads the
// `pkg-node/` build of the library, which targets `--target nodejs` in
// wasm-pack.

const fs = require('fs');
const path = require('path');

// Resolve the workspace-root pkg-node build relative to this script.
const wasm = require(path.join(__dirname, '../../../pkg-node/kem_dem_wasm.js'));

const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Parse a 0x-prefixed big-endian 32-byte hex string into a BigInt. */
function beHexToBigInt(hex) {
    const clean = hex.replace(/^0x/, '').padStart(64, '0');
    return BigInt('0x' + clean);
}

/** Parse the wire-format ciphertext hex into an array of Fr BigInts. */
function ciphertextHexToFrArray(hexCiphertext) {
    const bytes = Buffer.from(hexCiphertext, 'hex');
    if (bytes.length % 32 !== 0) {
        throw new Error(`ciphertext length ${bytes.length} is not a multiple of 32`);
    }
    const elements = [];
    for (let i = 0; i < bytes.length; i += 32) {
        // Each element is 32 bytes little-endian per src/kemdem_functions.rs.
        let n = 0n;
        for (let j = 31; j >= 0; j--) {
            n = (n << 8n) | BigInt(bytes[i + j]);
        }
        if (n >= BN254_FR_MODULUS) {
            throw new Error(`ciphertext element ${i / 32} ≥ Fr modulus`);
        }
        elements.push(n);
    }
    return elements;
}

function main() {
    // ── 1. The plaintext vote we'll prove a property about ──────────
    const VOTE = 1n; // change to 0n to demo a "no" vote
    if (VOTE !== 0n && VOTE !== 1n) {
        throw new Error('demo policy: vote must be 0 or 1');
    }

    // ── 2. Keypair + encryption via the real WASM library ───────────
    const kp = wasm.ZkEncryptor.generateKeypair();
    console.log('BabyJubJub keypair (from kem-dem-wasm/ZkEncryptor):');
    console.log('  secretKey  :', kp.secretKey);
    console.log('  publicKey.x:', kp.publicKey.x);
    console.log('  publicKey.y:', kp.publicKey.y);

    const payloadHex = ['0x' + VOTE.toString(16).padStart(64, '0')];
    const ciphertextHex = wasm.ZkEncryptor.encrypt(
        kp.publicKey.x,
        kp.publicKey.y,
        payloadHex,
    );
    console.log('\nWire-format ciphertext:');
    console.log('  hex   :', ciphertextHex);
    console.log('  bytes :', ciphertextHex.length / 2);

    // Sanity: round-trip through the same library before trusting the
    // wire. Catches any encoding regression early.
    const decrypted = wasm.ZkEncryptor.decrypt(kp.secretKey, ciphertextHex);
    if (decrypted.length !== 1 || BigInt(decrypted[0]) !== VOTE) {
        throw new Error(
            `decrypt sanity check failed: got ${decrypted.join(',')}, want 0x${VOTE.toString(16)}`,
        );
    }
    console.log('  decrypt roundtrip: OK');

    // ── 3. Convert to Circom-friendly decimal Fr strings ────────────
    const ciphertextFr = ciphertextHexToFrArray(ciphertextHex);
    const skFr = beHexToBigInt(kp.secretKey);

    // The BabyJubJub subgroup order ℓ ≈ 2.74 × 10^75. The Rust side
    // reduces the random seed mod ℓ; the BigInt we read out of the
    // hex is already < ℓ. Sanity-check it fits in 253 bits so
    // Num2Bits_strict accepts it inside the circuit.
    if (skFr >> 253n !== 0n) {
        throw new Error('secret key does not fit in 253 bits — circuit will reject');
    }

    const circomInput = {
        // Public (matches `signal input ciphertext[n + 2]` in the circuit)
        ciphertext: ciphertextFr.map((n) => n.toString()),
        // Private witness
        sk: skFr.toString(),
        payload: [VOTE.toString()],
    };

    // ── 4. Write inputs ─────────────────────────────────────────────
    const inputsDir = path.join(__dirname, '../inputs');
    fs.mkdirSync(inputsDir, { recursive: true });

    const inputPath = path.join(inputsDir, 'input.json');
    fs.writeFileSync(inputPath, JSON.stringify(circomInput, null, 2));
    console.log('\nWrote full witness ->', path.relative(process.cwd(), inputPath));

    const publicInput = { ciphertext: circomInput.ciphertext };
    const publicPath = path.join(inputsDir, 'public.json');
    fs.writeFileSync(publicPath, JSON.stringify(publicInput, null, 2));
    console.log('Wrote public input ->', path.relative(process.cwd(), publicPath));
}

try {
    main();
} catch (err) {
    console.error('generate-input failed:', err.stack || err);
    process.exit(1);
}
