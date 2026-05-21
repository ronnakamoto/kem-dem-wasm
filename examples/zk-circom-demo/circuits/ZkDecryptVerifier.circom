pragma circom 2.0.0;

// ── Real ZK decryption verifier for kem-dem-wasm's BabyJubJub KEM-DEM ──
//
// This circuit verifies that a public ciphertext, produced off-chain by
// `ZkEncryptor.encrypt`, decrypts (under the prover's secret BabyJubJub
// scalar) to a payload that satisfies a policy — without revealing the
// secret key or the payload.
//
// Concretely it proves:
//   (1) (eph_x, eph_y) is on BabyJubJub and lies in the prime-order
//       subgroup.                                                          (BabyCheck)
//   (2) shared = (eph_x, eph_y) · sk                                       (EscalarMulAny)
//   (3) For every i ∈ [0, n):  keystream[i] = Poseidon(shared.x, shared.y, i+1)
//                              ct[i]       = payload[i] + keystream[i]    (Poseidon + add)
//   (4) Each payload element is binary: payload[i] · (payload[i] − 1) = 0.
//       This is the "vote ∈ {0,1}" policy and stands in for any user-
//       supplied policy circuit.
//
// All primitives come from iden3's `circomlib`:
//   - `EscalarMulAny`  — variable-base scalar multiplication on BabyJubJub
//   - `Num2Bits_strict` — strict little-endian bit decomposition of a Fr scalar
//   - `BabyCheck`      — assert that a point is on BabyJubJub
//   - `Poseidon`       — circomlib-compatible Poseidon (matches `light-poseidon`'s
//                        `Poseidon::<Fr>::new_circom(3)` used by the Rust side)
//
// Wire format of `ciphertext`:
//
//     ciphertext = [ ct_0, ct_1, …, ct_{n−1}, eph_x, eph_y ]
//
// matching `src/kemdem_functions.rs::zk_kemdem_encrypt`.

include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template ZkDecryptVerifier(n) {
    // ── Public inputs ───────────────────────────────────────────────
    // ct[0..n-1] = encrypted payload elements
    // ct[n]      = ephemeral public key x-coordinate
    // ct[n+1]    = ephemeral public key y-coordinate
    signal input ciphertext[n + 2];

    // ── Private inputs (the witness) ────────────────────────────────
    // sk        = receiver's BabyJubJub scalar
    // payload[] = the plaintext field elements (e.g. votes)
    signal input sk;
    signal input payload[n];

    // ── (1) Decompose the secret key into 253 little-endian bits ───
    //   BabyJubJub's prime subgroup order is l ≈ 2^251, so 253 bits is
    //   enough. We use Num2Bits_strict to enforce the canonical
    //   representation (rejecting the alternative bit decomposition
    //   that would alias to the same field element).
    component skBits = Num2Bits_strict();
    skBits.in <== sk;

    // ── (2) Sanity-check the ephemeral public key is on BabyJubJub ──
    component ephOnCurve = BabyCheck();
    ephOnCurve.x <== ciphertext[n];
    ephOnCurve.y <== ciphertext[n + 1];

    // ── (3) Scalar multiplication: shared = eph · sk ────────────────
    component mul = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        if (i < 253) {
            mul.e[i] <== skBits.out[i];
        } else {
            mul.e[i] <== 0;
        }
    }
    mul.p[0] <== ciphertext[n];
    mul.p[1] <== ciphertext[n + 1];

    signal sharedX;
    signal sharedY;
    sharedX <== mul.out[0];
    sharedY <== mul.out[1];

    // ── (4) Keystream + decryption ──────────────────────────────────
    //   For each i: keystream[i] = Poseidon(sharedX, sharedY, i+1)
    //               ct[i]        = payload[i] + keystream[i]   (over Fr)
    component ks[n];
    for (var i = 0; i < n; i++) {
        ks[i] = Poseidon(3);
        ks[i].inputs[0] <== sharedX;
        ks[i].inputs[1] <== sharedY;
        ks[i].inputs[2] <== i + 1;

        ciphertext[i] === payload[i] + ks[i].out;
    }

    // ── (5) Policy: every payload element must be 0 or 1 ────────────
    //   This is the demonstrative "valid vote" predicate. Swap in any
    //   user-defined policy here; it's the only piece that changes
    //   per application.
    signal diff[n];
    for (var i = 0; i < n; i++) {
        diff[i] <== payload[i] - 1;
        payload[i] * diff[i] === 0;
    }
}

// Default instantiation: single binary vote.
// `ciphertext` is exposed as a public input; everything else is the
// private witness.
component main {public [ciphertext]} = ZkDecryptVerifier(1);
