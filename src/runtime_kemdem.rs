//! Curve-generic KEM-DEM core.
//!
//! Mirrors [`crate::kemdem_functions`]'s typed (default-curve only)
//! pipeline but drives all elliptic-curve arithmetic through the
//! runtime backend in [`crate::te_arith`], which is parameterized by
//! a [`crate::curve::Curve`] handle. The Poseidon stages are
//! curve-agnostic — they consume the shared-secret coordinates as
//! plain `Fr254` field elements — so the same hashes can be reused
//! verbatim. As a result, a ciphertext produced here on the default
//! curve is byte-identical to one produced by the typed pipeline.
//!
//! Wire format is unchanged:
//!
//! ```text
//! unauthenticated:  [ct_0 … ct_{n-1}] [ephem_x] [ephem_y]
//! authenticated:    [ct_0 … ct_{n-1}] [ephem_x] [ephem_y] [tag]
//! ```
//!
//! ## Scalars
//!
//! Scalars (the random `r` for encryption and the receiver's secret
//! key for decryption) arrive as raw 32-byte little-endian buffers.
//! The Montgomery ladder in [`crate::te_arith::scalar_mul`] treats
//! those bytes as a 256-bit unsigned integer and produces the same
//! point as `(seed mod scalar_order) · P` because the input point is
//! already in the prime-order subgroup.
//!
//! The `seed mod scalar_order == 0` case is detected post-hoc by
//! checking whether `seed · G` lands on the twisted-Edwards identity;
//! this avoids implementing a full 256-bit modular reduction in the
//! crate. The probability of accidental zero is `1 / scalar_order`,
//! which is negligible for a cryptographically meaningful curve.

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
use subtle::ConstantTimeEq;

use crate::curve::Curve;
use crate::kemdem_functions::{
    ZkKemDemError, EPHEM_AND_TAG_ELEMS, EPHEM_ELEMS, FR_BYTES, MAX_PAYLOAD_ELEMS,
};
use crate::te_arith::{is_in_subgroup, scalar_mul, TePoint};

// ── helpers ───────────────────────────────────────────────────────

/// Convert a 32-byte LE buffer into the `[u64; 4]` limb form expected
/// by [`crate::te_arith::scalar_mul`].
fn seed_to_limbs(seed: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&seed[i * 8..(i + 1) * 8]);
        *limb = u64::from_le_bytes(buf);
    }
    limbs
}

/// Validate that `(x, y)` is a usable receiver public key on `curve`:
/// not the identity, on-curve, and in the prime-order subgroup.
fn check_receiver_pub(curve: &Curve, x: Fr254, y: Fr254) -> Result<TePoint, ZkKemDemError> {
    // Identity rejection: every shared secret derived from the
    // identity collapses to the identity, so the keystream becomes
    // a fixed function of the counter alone.
    if x.is_zero() && y.is_one() {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "receiver public key is the identity",
        ));
    }
    let p = TePoint { x, y };
    if !p.is_on_curve(curve) {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "receiver public key is not on the supplied curve",
        ));
    }
    if !is_in_subgroup(curve, &p) {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "receiver public key is not in the prime-order subgroup",
        ));
    }
    Ok(p)
}

/// Validate a trailing ephemeral public key parsed from a ciphertext.
fn check_ephemeral(curve: &Curve, x: Fr254, y: Fr254) -> Result<TePoint, ZkKemDemError> {
    if x.is_zero() && y.is_one() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("identity point"));
    }
    let p = TePoint { x, y };
    if !p.is_on_curve(curve) {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "ephemeral public key is not on the supplied curve",
        ));
    }
    if !is_in_subgroup(curve, &p) {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "ephemeral public key is not in the prime-order subgroup",
        ));
    }
    Ok(p)
}

/// Compute `seed · P` and reject the (negligible-probability) case
/// where the product is the twisted-Edwards identity, which would
/// indicate `seed mod scalar_order == 0`.
fn scalar_mul_or_retry(curve: &Curve, p: &TePoint, seed: &[u8; 32]) -> Result<TePoint, ZkKemDemError> {
    let limbs = seed_to_limbs(seed);
    let result = scalar_mul(curve, p, &limbs);
    if result.is_identity() {
        return Err(ZkKemDemError::RetryNeeded);
    }
    Ok(result)
}

/// Poseidon keystream — identical formulation to
/// [`crate::kemdem_functions::generate_keystream`], but takes the
/// shared-secret coordinates directly so it works against either
/// arithmetic backend.
fn keystream(shared_x: Fr254, shared_y: Fr254, count: usize) -> Vec<Fr254> {
    let mut hasher = Poseidon::<Fr254>::new_circom(3)
        .expect("circomlib Poseidon(3) parameters are bundled in light-poseidon");
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let counter = Fr254::from((i as u64) + 1);
        let h = hasher
            .hash(&[shared_x, shared_y, counter])
            .expect("Poseidon hash over 3 Fr inputs never fails");
        out.push(h);
    }
    out
}

/// Poseidon-MAC — identical formulation to
/// [`crate::kemdem_functions::compute_mac_tag`].
fn mac_tag(
    shared_x: Fr254,
    shared_y: Fr254,
    ephem_x: Fr254,
    ephem_y: Fr254,
    ct_elements: &[Fr254],
) -> Fr254 {
    let mut hasher = Poseidon::<Fr254>::new_circom(3)
        .expect("circomlib Poseidon(3) parameters are bundled in light-poseidon");

    // Counter 0 is reserved for MAC use; keystream uses counters 1..=n.
    let mut state = hasher
        .hash(&[shared_x, shared_y, Fr254::from(0u64)])
        .expect("Poseidon hash over 3 Fr inputs never fails");

    for (i, ct) in ct_elements.iter().enumerate() {
        let counter = Fr254::from((i as u64) + 1);
        state = hasher
            .hash(&[state, *ct, counter])
            .expect("Poseidon hash over 3 Fr inputs never fails");
    }

    hasher
        .hash(&[state, ephem_x, ephem_y])
        .expect("Poseidon hash over 3 Fr inputs never fails")
}

#[inline]
fn fr_ct_eq(a: &Fr254, b: &Fr254) -> bool {
    let mut a_bytes = a.into_bigint().to_bytes_le();
    let mut b_bytes = b.into_bigint().to_bytes_le();
    a_bytes.resize(FR_BYTES, 0);
    b_bytes.resize(FR_BYTES, 0);
    a_bytes.ct_eq(&b_bytes).into()
}

fn encode_elements_le_hex(elements: &[Fr254]) -> String {
    let mut bytes = Vec::with_capacity(elements.len() * FR_BYTES);
    for el in elements {
        let mut le = el.into_bigint().to_bytes_le();
        le.resize(FR_BYTES, 0);
        bytes.extend_from_slice(&le);
    }
    hex::encode(&bytes)
}

fn decode_elements_le_hex(ciphertext_hex: &str) -> Result<Vec<Fr254>, ZkKemDemError> {
    let bytes = hex::decode(ciphertext_hex.trim_start_matches("0x"))
        .map_err(|e| ZkKemDemError::InvalidHex(e.to_string()))?;
    if bytes.len() % FR_BYTES != 0 {
        return Err(ZkKemDemError::MalformedCiphertext(format!(
            "ciphertext length {} is not a multiple of {FR_BYTES}",
            bytes.len()
        )));
    }
    let count = bytes.len() / FR_BYTES;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut chunk = [0u8; FR_BYTES];
        chunk.copy_from_slice(&bytes[i * FR_BYTES..(i + 1) * FR_BYTES]);
        out.push(Fr254::from_le_bytes_mod_order(&chunk));
    }
    Ok(out)
}

// ── public surface ────────────────────────────────────────────────

/// Curve-generic encrypt. See [`crate::kemdem_functions::zk_kemdem_encrypt`].
pub fn encrypt(
    curve: &Curve,
    seed: &[u8; 32],
    receiver_pub_x: Fr254,
    receiver_pub_y: Fr254,
    payload: &[Fr254],
) -> Result<String, ZkKemDemError> {
    if payload.len() > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let receiver = check_receiver_pub(curve, receiver_pub_x, receiver_pub_y)?;
    let g = TePoint {
        x: curve.gx,
        y: curve.gy,
    };
    let ephemeral = scalar_mul_or_retry(curve, &g, seed)?;
    let shared = scalar_mul_or_retry(curve, &receiver, seed)?;

    let ks = keystream(shared.x, shared.y, payload.len());
    let mut elements: Vec<Fr254> = Vec::with_capacity(payload.len() + EPHEM_ELEMS);
    for i in 0..payload.len() {
        elements.push(payload[i] + ks[i]);
    }
    elements.push(ephemeral.x);
    elements.push(ephemeral.y);
    Ok(encode_elements_le_hex(&elements))
}

/// Curve-generic decrypt. See [`crate::kemdem_functions::zk_kemdem_decrypt`].
pub fn decrypt(
    curve: &Curve,
    receiver_sec_key: &[u8; 32],
    ciphertext_hex: &str,
) -> Result<Vec<Fr254>, ZkKemDemError> {
    let elements = decode_elements_le_hex(ciphertext_hex)?;
    if elements.len() < EPHEM_ELEMS {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "ciphertext too short: missing trailing (x, y)",
        ));
    }
    let payload_len = elements.len() - EPHEM_ELEMS;
    if payload_len > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload_len,
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let ephem = check_ephemeral(curve, elements[payload_len], elements[payload_len + 1])?;
    let shared = scalar_mul_or_retry(curve, &ephem, receiver_sec_key)?;

    let ks = keystream(shared.x, shared.y, payload_len);
    let mut plaintext = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        plaintext.push(elements[i] - ks[i]);
    }
    Ok(plaintext)
}

/// Curve-generic authenticated encrypt. See
/// [`crate::kemdem_functions::zk_kemdem_encrypt_authenticated`].
pub fn encrypt_authenticated(
    curve: &Curve,
    seed: &[u8; 32],
    receiver_pub_x: Fr254,
    receiver_pub_y: Fr254,
    payload: &[Fr254],
) -> Result<String, ZkKemDemError> {
    if payload.len() > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let receiver = check_receiver_pub(curve, receiver_pub_x, receiver_pub_y)?;
    let g = TePoint {
        x: curve.gx,
        y: curve.gy,
    };
    let ephemeral = scalar_mul_or_retry(curve, &g, seed)?;
    let shared = scalar_mul_or_retry(curve, &receiver, seed)?;

    let ks = keystream(shared.x, shared.y, payload.len());
    let mut ct_elements: Vec<Fr254> = Vec::with_capacity(payload.len());
    for i in 0..payload.len() {
        ct_elements.push(payload[i] + ks[i]);
    }
    let tag = mac_tag(shared.x, shared.y, ephemeral.x, ephemeral.y, &ct_elements);

    let mut out: Vec<Fr254> = Vec::with_capacity(payload.len() + EPHEM_AND_TAG_ELEMS);
    out.extend_from_slice(&ct_elements);
    out.push(ephemeral.x);
    out.push(ephemeral.y);
    out.push(tag);
    Ok(encode_elements_le_hex(&out))
}

/// Curve-generic authenticated decrypt. See
/// [`crate::kemdem_functions::zk_kemdem_decrypt_authenticated`].
pub fn decrypt_authenticated(
    curve: &Curve,
    receiver_sec_key: &[u8; 32],
    ciphertext_hex: &str,
) -> Result<Vec<Fr254>, ZkKemDemError> {
    let elements = decode_elements_le_hex(ciphertext_hex)?;
    if elements.len() < EPHEM_AND_TAG_ELEMS {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "ciphertext too short: missing trailing (x, y, tag)",
        ));
    }
    let payload_len = elements.len() - EPHEM_AND_TAG_ELEMS;
    if payload_len > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload_len,
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let ephem_x = elements[payload_len];
    let ephem_y = elements[payload_len + 1];
    let received_tag = elements[payload_len + 2];

    let ephem = check_ephemeral(curve, ephem_x, ephem_y)?;
    let shared = scalar_mul_or_retry(curve, &ephem, receiver_sec_key)?;

    let ct_slice = &elements[..payload_len];
    let expected = mac_tag(shared.x, shared.y, ephem.x, ephem.y, ct_slice);
    if !fr_ct_eq(&expected, &received_tag) {
        return Err(ZkKemDemError::MacMismatch);
    }

    let ks = keystream(shared.x, shared.y, payload_len);
    let mut plaintext = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        plaintext.push(ct_slice[i] - ks[i]);
    }
    Ok(plaintext)
}

/// Derive a public key from a 32-byte seed/secret-key on `curve`.
/// Returns `(seed_le_bytes, pk_x, pk_y)`. The `seed_le_bytes` is
/// returned unchanged so callers have a single canonical form to
/// store alongside the public key.
pub fn keypair_from_seed(
    curve: &Curve,
    seed: &[u8; 32],
) -> Result<([u8; 32], Fr254, Fr254), ZkKemDemError> {
    let g = TePoint {
        x: curve.gx,
        y: curve.gy,
    };
    let pk = scalar_mul_or_retry(curve, &g, seed)?;
    Ok((*seed, pk.x, pk.y))
}
