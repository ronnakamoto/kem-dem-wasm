//! ZK-friendly BabyJubJub KEM-DEM over the BN254 scalar field.
//!
//! ## Wire format
//!
//! A ciphertext is a sequence of 32-byte little-endian field elements:
//!
//! ```text
//! [ct_0] [ct_1] … [ct_{n-1}] [ephemeral_x] [ephemeral_y]
//! ```
//!
//! Total size: `(n + 2) * 32` bytes. The ephemeral public key is stored
//! **uncompressed** so a verifying circuit does not have to compute a
//! sqrt from `y` to recover `x` (which is expensive in R1CS).
//!
//! ## KEM
//!
//! Standard ElGamal-style ephemeral exchange on BabyJubJub:
//! `ephemeral = G * r`, `shared = receiver_pub * r`.
//!
//! ## DEM
//!
//! A Poseidon-based stream cipher. For each payload element `i`:
//!
//! ```text
//! keystream[i] = Poseidon([shared.x, shared.y, Fr(i + 1)])
//! ciphertext[i] = payload[i] + keystream[i]   (in Fr)
//! ```
//!
//! Poseidon parameters are the iden3 `circomlib` parameters
//! (`PoseidonEx(t=4)`, full rounds 8, partial rounds 56), so the same
//! constants used by [`light-poseidon::Poseidon::<Fr>::new_circom(3)`]
//! match `circomlib`'s `Poseidon(3)` template byte-for-byte.

use ark_bn254::Fr as Fr254;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::fmt;
use std::ops::Add;
use subtle::ConstantTimeEq;
use taceo_ark_babyjubjub::{EdwardsAffine, EdwardsProjective, Fr as BabyJubJubScalar};

/// Structured errors from the ZK KEM-DEM. Distinguishing `RetryNeeded`
/// from real failures lets the caller's retry loop key off a variant
/// instead of fragile substring matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkKemDemError {
    /// The CSPRNG draw reduced to the zero scalar. The caller should
    /// draw a fresh seed and retry. Probability ≈ 1/r ≈ 2⁻²⁵¹.
    RetryNeeded,
    /// The payload exceeds [`MAX_PAYLOAD_ELEMS`].
    PayloadTooLarge { len: usize, max: usize },
    /// The ciphertext bytes were not a multiple of [`FR_BYTES`].
    MalformedCiphertext(String),
    /// The trailing ephemeral public key was missing, off-curve, in
    /// the wrong subgroup, or the identity element.
    InvalidEphemeralPoint(&'static str),
    /// Generic invalid-hex error from `hex::decode`.
    InvalidHex(String),
    /// The authenticated DEM's Poseidon tag did not match. The
    /// ciphertext was tampered with, the wrong key was used, or the
    /// caller passed an unauthenticated ciphertext to the
    /// authenticated decrypt.
    MacMismatch,
}

impl fmt::Display for ZkKemDemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkKemDemError::RetryNeeded => {
                f.write_str("ephemeral scalar is zero; retry with fresh randomness")
            }
            ZkKemDemError::PayloadTooLarge { len, max } => write!(
                f,
                "payload too large: {len} elements exceeds maximum of {max}"
            ),
            ZkKemDemError::MalformedCiphertext(s) => write!(f, "malformed ciphertext: {s}"),
            ZkKemDemError::InvalidEphemeralPoint(s) => {
                write!(f, "invalid ephemeral public key: {s}")
            }
            ZkKemDemError::InvalidHex(s) => write!(f, "invalid ciphertext hex: {s}"),
            ZkKemDemError::MacMismatch => {
                f.write_str("authenticated ciphertext failed integrity check (MAC mismatch)")
            }
        }
    }
}

impl std::error::Error for ZkKemDemError {}

/// Number of bytes per Fr element on the wire.
pub const FR_BYTES: usize = 32;
/// Number of trailing Fr elements that encode the ephemeral public key
/// in the *unauthenticated* wire format.
pub const EPHEM_ELEMS: usize = 2;
/// Number of trailing Fr elements that encode the ephemeral public key
/// **and** the Poseidon MAC tag in the *authenticated* wire format.
pub const EPHEM_AND_TAG_ELEMS: usize = 3;
/// Maximum number of payload elements per encryption to bound memory
/// and computation (each element requires a Poseidon hash invocation).
pub const MAX_PAYLOAD_ELEMS: usize = 1024;

/// Encrypt `payload` (a slice of Fr elements) to `receiver_pub_key`.
///
/// `random_seed` is interpreted as a uniform 32-byte sample and reduced
/// mod the BabyJubJub scalar field to produce the ephemeral scalar `r`.
/// Callers MUST sample `random_seed` from a CSPRNG and never reuse it.
///
/// Returns a hex-encoded ciphertext, or an error if the seed reduces
/// to the zero scalar (callers should retry with a fresh CSPRNG sample).
pub fn zk_kemdem_encrypt(
    random_seed: [u8; 32],
    receiver_pub_key: &EdwardsAffine,
    payload: &[Fr254],
) -> Result<String, ZkKemDemError> {
    if payload.len() > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let r = BabyJubJubScalar::from_le_bytes_mod_order(&random_seed);
    if r.is_zero() {
        return Err(ZkKemDemError::RetryNeeded);
    }
    let ephemeral_pub: EdwardsAffine = (EdwardsProjective::generator() * r).into_affine();
    let shared_secret: EdwardsAffine = (*receiver_pub_key * r).into_affine();

    let keystream = generate_keystream(&shared_secret, payload.len());

    let mut elements: Vec<Fr254> = Vec::with_capacity(payload.len() + EPHEM_ELEMS);
    for i in 0..payload.len() {
        elements.push(payload[i].add(&keystream[i]));
    }
    elements.push(ephemeral_pub.x);
    elements.push(ephemeral_pub.y);

    Ok(encode_elements_le_hex(&elements))
}

/// Decrypt a hex-encoded ciphertext using `receiver_sec_key`.
pub fn zk_kemdem_decrypt(
    receiver_sec_key: &BabyJubJubScalar,
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

    let ephem_x = elements[payload_len];
    let ephem_y = elements[payload_len + 1];

    // Twisted-Edwards identity is (0, 1). The old check `(0, 0)` was a
    // no-op (that point is off-curve and would be caught by the
    // on-curve check anyway). The identity, by contrast, *is* on the
    // curve and *is* in the prime-order subgroup (every subgroup
    // contains the identity), so it must be rejected explicitly to
    // prevent degenerate shared secrets.
    if ephem_x.is_zero() && ephem_y.is_one() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("identity point"));
    }
    let ephemeral_pub = EdwardsAffine::new_unchecked(ephem_x, ephem_y);
    if !ephemeral_pub.is_on_curve() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("not on BabyJubJub"));
    }
    if !ephemeral_pub.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("wrong subgroup"));
    }

    let shared_secret: EdwardsAffine = (ephemeral_pub * *receiver_sec_key).into_affine();
    let keystream = generate_keystream(&shared_secret, payload_len);

    let mut plaintext = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        plaintext.push(elements[i] - keystream[i]);
    }
    Ok(plaintext)
}

/// Poseidon-based keystream.
///
/// `keystream[i] = Poseidon([shared.x, shared.y, Fr(i + 1)])`
///
/// Using `i + 1` as the counter (rather than `i`) is a domain
/// separator that prevents the trivial collision where a single
/// shared secret with an empty payload would hash to a constant.
fn generate_keystream(shared_secret: &EdwardsAffine, count: usize) -> Vec<Fr254> {
    let mut hasher = Poseidon::<Fr254>::new_circom(3)
        .expect("circomlib Poseidon(3) parameters are bundled in light-poseidon");
    let mut stream = Vec::with_capacity(count);
    for i in 0..count {
        let counter = Fr254::from((i as u64) + 1);
        let h = hasher
            .hash(&[shared_secret.x, shared_secret.y, counter])
            .expect("Poseidon hash over 3 Fr inputs never fails");
        stream.push(h);
    }
    stream
}

/// Constant-time equality check for two BN254 `Fr` elements.
///
/// Both sides are lowered to their canonical 32-byte little-endian
/// representation and compared via `subtle::ConstantTimeEq`. The
/// resulting branch on the returned `bool` is acceptable: the boolean
/// itself was derived in constant time, so an attacker cannot learn
/// *where* the tags differ, only that they differ.
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

// ─── BabyJubJub keypair helpers, used by the WASM facade ──────────

/// Generate a BabyJubJub keypair from a CSPRNG seed.
///
/// Returns an error if the seed reduces to the zero scalar (callers
/// should retry with a fresh CSPRNG sample).
pub fn generate_keypair_from_seed(
    seed: [u8; 32],
) -> Result<(BabyJubJubScalar, EdwardsAffine), ZkKemDemError> {
    let sk = BabyJubJubScalar::from_le_bytes_mod_order(&seed);
    if sk.is_zero() {
        return Err(ZkKemDemError::RetryNeeded);
    }
    let pk = (EdwardsProjective::generator() * sk).into_affine();
    Ok((sk, pk))
}

/// Reconstruct an `EdwardsAffine` from its raw `(x, y)` Fr254 coordinates
/// and verify it lies on the BabyJubJub curve, in the prime-order
/// subgroup, and is not the identity. Returns `None` for any invalid input.
pub fn point_from_xy(x: Fr254, y: Fr254) -> Option<EdwardsAffine> {
    // Reject the identity element (0, 1) of the twisted-Edwards group.
    // The identity is on-curve and in the prime-order subgroup, so the
    // subsequent checks would not catch it; an attacker supplying the
    // identity as the receiver's public key would force every shared
    // secret derived from it to also be the identity, making the
    // keystream trivially recomputable.
    //
    // Also reject (0, 0): off-curve, but the explicit check makes the
    // failure mode obvious to readers.
    if x.is_zero() && (y.is_zero() || y.is_one()) {
        return None;
    }
    let p = EdwardsAffine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return None;
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return None;
    }
    Some(p)
}

// ─── Authenticated DEM (Poseidon-based MAC) ──────────────────────
//
// Wire format for the authenticated variant:
//
//   [ct_0] [ct_1] … [ct_{n-1}] [ephem_x] [ephem_y] [tag]
//
// One extra Fr element (`tag`) versus the unauthenticated form. The
// tag is a Poseidon sponge over the ciphertext elements, bound to the
// shared secret and the ephemeral public key:
//
//   mac_key = Poseidon([shared.x, shared.y, Fr(0)])
//     (counter 0 is reserved for the MAC; the keystream uses counters
//      1..=n, so there is no collision between the two PRF strands.)
//
//   state = mac_key
//   for i in 0..n:
//     state = Poseidon([state, ct[i], Fr(i + 1)])
//   tag = Poseidon([state, ephem.x, ephem.y])
//
// Properties:
// - Confidentiality: unchanged from the unauthenticated DEM.
// - Integrity: SUF-CMA under Poseidon-as-PRF; any flipped ciphertext
//   bit, swapped element, or substituted ephemeral key changes the
//   recomputed tag.
// - Circuit cost: O(n) Poseidon(3) calls for the MAC plus the
//   existing O(n) for the keystream. Same Poseidon primitive
//   throughout, so circuit-side reuse is trivial.

/// Compute the Poseidon MAC tag over `ct_elements ‖ ephemeral_pub`,
/// bound to `shared_secret`. Used by both the authenticated encrypt
/// and authenticated decrypt paths.
fn compute_mac_tag(
    shared_secret: &EdwardsAffine,
    ephemeral_pub: &EdwardsAffine,
    ct_elements: &[Fr254],
) -> Fr254 {
    let mut hasher = Poseidon::<Fr254>::new_circom(3)
        .expect("circomlib Poseidon(3) parameters are bundled in light-poseidon");

    // Derive a per-session MAC key. Counter 0 is reserved for MAC use;
    // keystream uses counters 1..=n, so the two PRF domains do not
    // overlap.
    let mut state = hasher
        .hash(&[shared_secret.x, shared_secret.y, Fr254::from(0u64)])
        .expect("Poseidon hash over 3 Fr inputs never fails");

    // Absorb each ciphertext element with its position.
    for (i, ct) in ct_elements.iter().enumerate() {
        let counter = Fr254::from((i as u64) + 1);
        state = hasher
            .hash(&[state, *ct, counter])
            .expect("Poseidon hash over 3 Fr inputs never fails");
    }

    // Bind the ephemeral public key so a malicious sender cannot swap
    // the ephemeral key while keeping the ct stream intact.
    hasher
        .hash(&[state, ephemeral_pub.x, ephemeral_pub.y])
        .expect("Poseidon hash over 3 Fr inputs never fails")
}

/// Authenticated counterpart of [`zk_kemdem_encrypt`]. Returns a hex
/// ciphertext that includes a 1-element Poseidon MAC tag.
pub fn zk_kemdem_encrypt_authenticated(
    random_seed: [u8; 32],
    receiver_pub_key: &EdwardsAffine,
    payload: &[Fr254],
) -> Result<String, ZkKemDemError> {
    if payload.len() > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let r = BabyJubJubScalar::from_le_bytes_mod_order(&random_seed);
    if r.is_zero() {
        return Err(ZkKemDemError::RetryNeeded);
    }
    let ephemeral_pub: EdwardsAffine = (EdwardsProjective::generator() * r).into_affine();
    let shared_secret: EdwardsAffine = (*receiver_pub_key * r).into_affine();

    let keystream = generate_keystream(&shared_secret, payload.len());
    let mut ct_elements: Vec<Fr254> = Vec::with_capacity(payload.len());
    for i in 0..payload.len() {
        ct_elements.push(payload[i].add(&keystream[i]));
    }

    let tag = compute_mac_tag(&shared_secret, &ephemeral_pub, &ct_elements);

    let mut out: Vec<Fr254> = Vec::with_capacity(payload.len() + EPHEM_AND_TAG_ELEMS);
    out.extend_from_slice(&ct_elements);
    out.push(ephemeral_pub.x);
    out.push(ephemeral_pub.y);
    out.push(tag);

    Ok(encode_elements_le_hex(&out))
}

/// Authenticated counterpart of [`zk_kemdem_decrypt`]. Verifies the
/// Poseidon MAC tag in constant time *before* decrypting; returns
/// [`ZkKemDemError::MacMismatch`] on tampering.
pub fn zk_kemdem_decrypt_authenticated(
    receiver_sec_key: &BabyJubJubScalar,
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

    if ephem_x.is_zero() && ephem_y.is_one() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("identity point"));
    }
    let ephemeral_pub = EdwardsAffine::new_unchecked(ephem_x, ephem_y);
    if !ephemeral_pub.is_on_curve() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("not on BabyJubJub"));
    }
    if !ephemeral_pub.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("wrong subgroup"));
    }

    let shared_secret: EdwardsAffine = (ephemeral_pub * *receiver_sec_key).into_affine();

    // Recompute the MAC over the received ciphertext slice and compare
    // the canonical little-endian byte form in constant time. `ark-ff`
    // makes NO timing guarantees on `PartialEq` for `Fr` elements, so
    // we lower both tags to their fixed-size byte representation and
    // use `subtle::ConstantTimeEq` to avoid leaking which byte differs
    // (which would otherwise allow a forgery-by-timing attack on the
    // tag).
    let ct_slice = &elements[..payload_len];
    let expected_tag = compute_mac_tag(&shared_secret, &ephemeral_pub, ct_slice);
    if !fr_ct_eq(&expected_tag, &received_tag) {
        return Err(ZkKemDemError::MacMismatch);
    }

    // MAC verified — now decrypt.
    let keystream = generate_keystream(&shared_secret, payload_len);
    let mut plaintext = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        plaintext.push(ct_slice[i] - keystream[i]);
    }
    Ok(plaintext)
}

// ─── Two-level KEM-DEM with caller-supplied domain separators ────
//
// This extends the crate with a generic two-level KEM-DEM that any
// protocol can use by supplying its own Poseidon domain constants and
// choosing an EPK encoding. Any protocol sharing the same key material but
// requiring cryptographic separation can pass its own constants.
//
// Wire format (both `compress_epk` variants produce `(n + 2)` elements):
//
//   compress_epk = false  →  [ct_0 … ct_{n-1}] [epk_x] [epk_y]
//   compress_epk = true   →  [ct_0 … ct_{n-1}] [epk_y] [sign_flag]

/// Configuration for a custom two-level KEM-DEM keystream.
///
/// Domain constants provide cryptographic separation between the KEM
/// and DEM layers and — crucially — between different protocols that
/// share the same BabyJubJub key material.
///
/// **Convention for deriving domain constants:**
/// ```text
/// kem_domain = Fr254::from_le_bytes_mod_order(SHA256("ProtocolName|PurposeKEM"))
/// dem_domain = Fr254::from_le_bytes_mod_order(SHA256("ProtocolName|PurposeDEM"))
/// ```
/// Collision between two protocols' domain constants makes their
/// ciphertexts cross-decryptable — choose unique, descriptive strings.
pub struct KemDemDomains {
    /// Domain separator fed into the KEM step.
    /// `enc_key = Poseidon([shared.x, shared.y, kem_domain])`
    pub kem_domain: Fr254,
    /// Domain separator fed into each DEM element.
    /// `keystream[i] = Poseidon([enc_key, dem_domain, Fr(i)])`
    pub dem_domain: Fr254,
}

/// Two-level Poseidon keystream with caller-supplied domain separators.
///
/// Unlike the built-in [`generate_keystream`] (which uses a single Poseidon
/// call per element with a **1-based** `i+1` counter — reserving counter 0
/// for the MAC key), this function first derives an intermediate encryption
/// key from the shared secret and a KEM domain constant, then derives each
/// keystream element from that key using a DEM domain constant and a
/// **0-based** counter.
///
/// The 0-based counter is safe here because the domain constants provide
/// the separation that the 1-based counter provides in the single-level
/// scheme (where counter 0 is reserved for the MAC strand).
///
/// This matches the pattern used by protocols that require
/// cryptographic separation between the KEM and DEM layers.
pub(crate) fn generate_keystream_with_domains(
    shared_secret: &EdwardsAffine,
    count: usize,
    domains: &KemDemDomains,
) -> Vec<Fr254> {
    let mut hasher =
        Poseidon::<Fr254>::new_circom(3).expect("circomlib Poseidon(3) parameters are bundled");
    let enc_key = hasher
        .hash(&[shared_secret.x, shared_secret.y, domains.kem_domain])
        .expect("Poseidon hash over 3 Fr inputs never fails");
    (0..count)
        .map(|i| {
            hasher
                .hash(&[enc_key, domains.dem_domain, Fr254::from(i as u64)])
                .expect("Poseidon hash over 3 Fr inputs never fails")
        })
        .collect()
}

/// Generic encrypt: two-level KEM-DEM with caller-supplied domain constants
/// and configurable EPK encoding.
///
/// Wire format with `compress_epk = true` (compressed style):
///   `[ct_0 … ct_{n-1}] [epk_y] [epk_x_sign_flag]`
///
/// Wire format with `compress_epk = false` (default style, same as `encrypt`):
///   `[ct_0 … ct_{n-1}] [epk_x] [epk_y]`
///
/// **Confidentiality only.** For integrity protection, use
/// [`zk_kemdem_encrypt_authenticated_with_domains`] or verify the
/// ciphertext in a ZK circuit.
pub fn zk_kemdem_encrypt_with_domains(
    random_seed: [u8; 32],
    receiver_pub_key: &EdwardsAffine,
    payload: &[Fr254],
    domains: &KemDemDomains,
    compress_epk: bool,
) -> Result<String, ZkKemDemError> {
    if payload.len() > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let r = BabyJubJubScalar::from_le_bytes_mod_order(&random_seed);
    if r.is_zero() {
        return Err(ZkKemDemError::RetryNeeded);
    }
    let ephemeral_pub: EdwardsAffine = (EdwardsProjective::generator() * r).into_affine();
    let shared_secret: EdwardsAffine = (*receiver_pub_key * r).into_affine();

    let keystream = generate_keystream_with_domains(&shared_secret, payload.len(), domains);
    let mut elements: Vec<Fr254> = Vec::with_capacity(payload.len() + EPHEM_ELEMS);
    for i in 0..payload.len() {
        elements.push(payload[i] + keystream[i]);
    }

    append_epk(&mut elements, &ephemeral_pub, compress_epk);

    Ok(encode_elements_le_hex(&elements))
}

/// Generic decrypt: counterpart to [`zk_kemdem_encrypt_with_domains`].
///
/// Set `compress_epk = true` when the ciphertext was produced with
/// `compress_epk = true`; the last two elements are then treated as
/// `[epk_y, sign_flag]` and the full EPK is reconstructed via Ark's
/// compressed-point deserialiser.
pub fn zk_kemdem_decrypt_with_domains(
    receiver_sec_key: &BabyJubJubScalar,
    ciphertext_hex: &str,
    domains: &KemDemDomains,
    compress_epk: bool,
) -> Result<Vec<Fr254>, ZkKemDemError> {
    let elements = decode_elements_le_hex(ciphertext_hex)?;
    if elements.len() < EPHEM_ELEMS {
        return Err(ZkKemDemError::InvalidEphemeralPoint("ciphertext too short"));
    }
    let payload_len = elements.len() - EPHEM_ELEMS;
    if payload_len > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload_len,
            max: MAX_PAYLOAD_ELEMS,
        });
    }

    let ephemeral_pub = decode_epk(&elements, payload_len, compress_epk)?;

    let shared_secret: EdwardsAffine = (ephemeral_pub * *receiver_sec_key).into_affine();
    let keystream = generate_keystream_with_domains(&shared_secret, payload_len, domains);

    Ok((0..payload_len)
        .map(|i| elements[i] - keystream[i])
        .collect())
}

// ─── Shared EPK encoding/decoding helpers ────────────────────────
//
// Both the unauthenticated and authenticated domain-separated
// variants need to encode/decode the ephemeral public key in the
// same way.  These helpers centralise that logic.

/// Append the ephemeral public key to `elements` in either compressed
/// or uncompressed form.
fn append_epk(elements: &mut Vec<Fr254>, ephemeral_pub: &EdwardsAffine, compress: bool) {
    if compress {
        // Compressed: [epk_y, sign_flag]
        // sign_flag = Fr254::one() if epk.x > -epk.x in canonical BigInteger
        // representation (matches Ark's compressed-point convention).
        let neg_x = -ephemeral_pub.x;
        let sign_flag = if ephemeral_pub.x.into_bigint() > neg_x.into_bigint() {
            Fr254::one()
        } else {
            Fr254::zero()
        };
        elements.push(ephemeral_pub.y);
        elements.push(sign_flag);
    } else {
        // Uncompressed: [epk_x, epk_y]  (same as the standard encrypt)
        elements.push(ephemeral_pub.x);
        elements.push(ephemeral_pub.y);
    }
}

/// Decode the ephemeral public key from the trailing elements of a
/// ciphertext, validating curve membership, subgroup order, and
/// rejecting the identity.
fn decode_epk(
    elements: &[Fr254],
    payload_len: usize,
    compress: bool,
) -> Result<EdwardsAffine, ZkKemDemError> {
    let ephemeral_pub = if compress {
        let epk_y = elements[payload_len];
        let sign_flag = elements[payload_len + 1];

        // Validate that the sign flag is 0 or 1. A malicious ciphertext
        // could set arbitrary bits, which would corrupt the reconstructed
        // point after the MSB shift.
        if !sign_flag.is_zero() && !sign_flag.is_one() {
            return Err(ZkKemDemError::InvalidEphemeralPoint(
                "compressed sign flag must be 0 or 1",
            ));
        }

        // Reconstruct Ark compressed point: 32-byte LE y, sign bit in MSB.
        let mut point_bytes = epk_y.into_bigint().to_bytes_le();
        point_bytes.resize(32, 0);
        point_bytes[31] |= sign_flag.into_bigint().to_bytes_le()[0] << 7;

        use ark_serialize::CanonicalDeserialize;
        EdwardsAffine::deserialize_compressed(point_bytes.as_slice())
            .map_err(|_| ZkKemDemError::InvalidEphemeralPoint("decompression failed"))?
    } else {
        let epk_x = elements[payload_len];
        let epk_y = elements[payload_len + 1];

        // Reject the identity element (0, 1) of the twisted-Edwards
        // group. The identity is on-curve and in the prime-order
        // subgroup, so the subsequent checks would not catch it.
        if epk_x.is_zero() && epk_y.is_one() {
            return Err(ZkKemDemError::InvalidEphemeralPoint("identity point"));
        }

        let p = EdwardsAffine::new_unchecked(epk_x, epk_y);
        if !p.is_on_curve() {
            return Err(ZkKemDemError::InvalidEphemeralPoint("not on BabyJubJub"));
        }
        p
    };

    // Reject the identity regardless of how it was decoded. The
    // identity is in the prime-order subgroup (every subgroup contains
    // the identity), so the subgroup check below would pass.  An
    // attacker supplying the identity as the EPK forces every shared
    // secret to also be the identity, making the keystream trivially
    // recomputable.
    if ephemeral_pub.x.is_zero() && ephemeral_pub.y.is_one() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("identity point"));
    }

    if !ephemeral_pub.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZkKemDemError::InvalidEphemeralPoint("wrong subgroup"));
    }

    Ok(ephemeral_pub)
}

// ─── Authenticated two-level KEM-DEM with domain separators ──────
//
// Wire format for the authenticated domain-separated variant:
//
//   compress_epk = false  →  [ct_0 … ct_{n-1}] [epk_x] [epk_y] [tag]
//   compress_epk = true   →  [ct_0 … ct_{n-1}] [epk_y] [sign]  [tag]
//
// One extra Fr element (`tag`) versus the unauthenticated form. The
// MAC key is derived from the intermediate encryption key (enc_key)
// and both domain constants, so it is domain-separated from both the
// keystream and from other protocols' MAC keys:
//
//   enc_key = Poseidon([shared.x, shared.y, kem_domain])
//   mac_key = Poseidon([enc_key, kem_domain, dem_domain])
//
// The mac_key input pattern `[enc_key, kem_domain, dem_domain]` is
// structurally distinct from any DEM keystream element `[enc_key,
// dem_domain, counter]` (the second slot differs), so there is no
// collision between the MAC and keystream PRF strands.
//
//   state = mac_key
//   for i in 0..n:
//     state = Poseidon([state, ct[i], Fr(i + 1)])
//   tag = Poseidon([state, epk_component_0, epk_component_1])

/// Compute the Poseidon MAC tag for the domain-separated variant.
///
/// `epk_elem_0`/`epk_elem_1` are the two trailing EPK elements in
/// whichever encoding was used (compressed or uncompressed). Binding
/// them into the tag prevents EPK substitution attacks.
fn compute_mac_tag_with_domains(
    enc_key: Fr254,
    domains: &KemDemDomains,
    epk_elem_0: Fr254,
    epk_elem_1: Fr254,
    ct_elements: &[Fr254],
) -> Fr254 {
    let mut hasher = Poseidon::<Fr254>::new_circom(3)
        .expect("circomlib Poseidon(3) parameters are bundled in light-poseidon");

    // Derive a per-session MAC key from the enc_key and both domain
    // constants. This is structurally distinct from the keystream
    // derivation `Poseidon([enc_key, dem_domain, i])` because the
    // second slot is `kem_domain` (not `dem_domain`).
    let mut state = hasher
        .hash(&[enc_key, domains.kem_domain, domains.dem_domain])
        .expect("Poseidon hash over 3 Fr inputs never fails");

    // Absorb each ciphertext element with its position.
    for (i, ct) in ct_elements.iter().enumerate() {
        let counter = Fr254::from((i as u64) + 1);
        state = hasher
            .hash(&[state, *ct, counter])
            .expect("Poseidon hash over 3 Fr inputs never fails");
    }

    // Bind the ephemeral public key (in whichever encoding was used).
    hasher
        .hash(&[state, epk_elem_0, epk_elem_1])
        .expect("Poseidon hash over 3 Fr inputs never fails")
}

/// Authenticated counterpart of [`zk_kemdem_encrypt_with_domains`].
/// Returns a hex ciphertext that includes a 1-element Poseidon MAC tag.
///
/// Wire format: `[ct_0 … ct_{n-1}] [epk_0] [epk_1] [tag]`
/// Total: `(payload.len() + 3) * 32` bytes.
pub fn zk_kemdem_encrypt_authenticated_with_domains(
    random_seed: [u8; 32],
    receiver_pub_key: &EdwardsAffine,
    payload: &[Fr254],
    domains: &KemDemDomains,
    compress_epk: bool,
) -> Result<String, ZkKemDemError> {
    if payload.len() > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD_ELEMS,
        });
    }
    let r = BabyJubJubScalar::from_le_bytes_mod_order(&random_seed);
    if r.is_zero() {
        return Err(ZkKemDemError::RetryNeeded);
    }
    let ephemeral_pub: EdwardsAffine = (EdwardsProjective::generator() * r).into_affine();
    let shared_secret: EdwardsAffine = (*receiver_pub_key * r).into_affine();

    let keystream = generate_keystream_with_domains(&shared_secret, payload.len(), domains);
    let mut ct_elements: Vec<Fr254> = Vec::with_capacity(payload.len());
    for i in 0..payload.len() {
        ct_elements.push(payload[i] + keystream[i]);
    }

    // Derive the intermediate enc_key for MAC computation.
    let mut hasher =
        Poseidon::<Fr254>::new_circom(3).expect("circomlib Poseidon(3) parameters are bundled");
    let enc_key = hasher
        .hash(&[shared_secret.x, shared_secret.y, domains.kem_domain])
        .expect("Poseidon hash over 3 Fr inputs never fails");

    // Build EPK elements for the tag — must match what goes on the wire.
    let mut epk_elems: Vec<Fr254> = Vec::with_capacity(2);
    append_epk(&mut epk_elems, &ephemeral_pub, compress_epk);

    let tag =
        compute_mac_tag_with_domains(enc_key, domains, epk_elems[0], epk_elems[1], &ct_elements);

    let mut out: Vec<Fr254> = Vec::with_capacity(payload.len() + EPHEM_AND_TAG_ELEMS);
    out.extend_from_slice(&ct_elements);
    out.extend_from_slice(&epk_elems);
    out.push(tag);

    Ok(encode_elements_le_hex(&out))
}

/// Authenticated counterpart of [`zk_kemdem_decrypt_with_domains`].
/// Verifies the Poseidon MAC tag in constant time *before* decrypting;
/// returns [`ZkKemDemError::MacMismatch`] on tampering.
pub fn zk_kemdem_decrypt_authenticated_with_domains(
    receiver_sec_key: &BabyJubJubScalar,
    ciphertext_hex: &str,
    domains: &KemDemDomains,
    compress_epk: bool,
) -> Result<Vec<Fr254>, ZkKemDemError> {
    let elements = decode_elements_le_hex(ciphertext_hex)?;
    if elements.len() < EPHEM_AND_TAG_ELEMS {
        return Err(ZkKemDemError::InvalidEphemeralPoint(
            "ciphertext too short: missing trailing (epk_0, epk_1, tag)",
        ));
    }
    let payload_len = elements.len() - EPHEM_AND_TAG_ELEMS;
    if payload_len > MAX_PAYLOAD_ELEMS {
        return Err(ZkKemDemError::PayloadTooLarge {
            len: payload_len,
            max: MAX_PAYLOAD_ELEMS,
        });
    }

    let ephemeral_pub = decode_epk(&elements, payload_len, compress_epk)?;
    let received_tag = elements[payload_len + 2];

    let shared_secret: EdwardsAffine = (ephemeral_pub * *receiver_sec_key).into_affine();

    // Re-derive enc_key for MAC verification.
    let mut hasher =
        Poseidon::<Fr254>::new_circom(3).expect("circomlib Poseidon(3) parameters are bundled");
    let enc_key = hasher
        .hash(&[shared_secret.x, shared_secret.y, domains.kem_domain])
        .expect("Poseidon hash over 3 Fr inputs never fails");

    // Recompute the MAC over the received ciphertext and compare in
    // constant time (see `fr_ct_eq` doc for rationale).
    let ct_slice = &elements[..payload_len];
    let epk_elem_0 = elements[payload_len];
    let epk_elem_1 = elements[payload_len + 1];
    let expected_tag =
        compute_mac_tag_with_domains(enc_key, domains, epk_elem_0, epk_elem_1, ct_slice);
    if !fr_ct_eq(&expected_tag, &received_tag) {
        return Err(ZkKemDemError::MacMismatch);
    }

    // MAC verified — now decrypt.
    let keystream = generate_keystream_with_domains(&shared_secret, payload_len, domains);
    let mut plaintext = Vec::with_capacity(payload_len);
    for i in 0..payload_len {
        plaintext.push(ct_slice[i] - keystream[i]);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    fn rand_keypair_with<R: ark_std::rand::RngCore>(
        rng: &mut R,
    ) -> (BabyJubJubScalar, EdwardsAffine) {
        let sk = BabyJubJubScalar::rand(rng);
        let pk = (EdwardsProjective::generator() * sk).into_affine();
        (sk, pk)
    }

    fn rand_keypair() -> (BabyJubJubScalar, EdwardsAffine) {
        let mut rng = ark_std::test_rng();
        rand_keypair_with(&mut rng)
    }

    #[test]
    fn roundtrip_single_element() {
        let (sk, pk) = rand_keypair();
        let payload = vec![Fr254::from(42u64)];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let ct = zk_kemdem_encrypt(seed, &pk, &payload).unwrap();
        // Expected size: 1 payload + 2 ephem = 3 elements = 96 bytes = 192 hex chars
        assert_eq!(ct.len(), (1 + EPHEM_ELEMS) * FR_BYTES * 2);

        let pt = zk_kemdem_decrypt(&sk, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn roundtrip_multi_element() {
        let (sk, pk) = rand_keypair();
        let payload: Vec<Fr254> = (0..7).map(|i| Fr254::from(i as u64 * 31337)).collect();
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let ct = zk_kemdem_encrypt(seed, &pk, &payload).unwrap();
        let pt = zk_kemdem_decrypt(&sk, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn decrypt_wrong_key_does_not_recover_plaintext() {
        let mut rng = ark_std::test_rng();
        let (_, pk) = rand_keypair_with(&mut rng);
        let (other_sk, _) = rand_keypair_with(&mut rng);
        let payload = vec![Fr254::from(0xdeadbeefu64), Fr254::from(0xfeedf00du64)];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut rng, &mut seed);

        let ct = zk_kemdem_encrypt(seed, &pk, &payload).unwrap();
        let wrong = zk_kemdem_decrypt(&other_sk, &ct).unwrap();
        assert_ne!(wrong, payload);
    }

    #[test]
    fn rejects_invalid_curve_point() {
        // Fabricate a ciphertext whose ephemeral point is off-curve.
        let bytes = vec![0u8; FR_BYTES * 3]; // 1 ct + 2 ephem, all zeros
        let hex = hex::encode(&bytes);
        let (sk, _) = rand_keypair();
        let result = zk_kemdem_decrypt(&sk, &hex);
        assert!(result.is_err(), "(0,0) must be rejected");

        // Replace the y coordinate with a value that is not on the
        // curve given x = 1.
        let mut bytes = vec![0u8; FR_BYTES * 3];
        bytes[FR_BYTES] = 1; // ephem_x = 1
        bytes[2 * FR_BYTES] = 1; // ephem_y = 1
        let hex = hex::encode(&bytes);
        let result = zk_kemdem_decrypt(&sk, &hex);
        assert!(result.is_err(), "off-curve point must be rejected");
    }

    #[test]
    fn keystream_is_deterministic_and_position_dependent() {
        let (_, pk) = rand_keypair();
        let ks_a = generate_keystream(&pk, 3);
        let ks_b = generate_keystream(&pk, 3);
        assert_eq!(ks_a, ks_b, "keystream is deterministic in (point, count)");
        assert_ne!(
            ks_a[0], ks_a[1],
            "different positions produce different keys"
        );
        assert_ne!(ks_a[1], ks_a[2]);
    }

    /// Pinned circomlib-Poseidon-compatible test vector. If this
    /// breaks, the keystream formula or Poseidon parameters changed —
    /// the Circom circuit will no longer accept ciphertexts from this
    /// library.
    ///
    /// Equivalent circomlibjs JavaScript:
    /// ```js
    /// const poseidon = await buildPoseidon();
    /// poseidon.F.toString(poseidon([1n, 2n, 1n]), 16)
    /// // => "1e05682c815341647510bf582454cca025584699f2419cbdea3205afb3506e5b"
    /// ```
    #[test]
    fn poseidon_keystream_pinned_vector() {
        let x = Fr254::from(1u64);
        let y = Fr254::from(2u64);
        let p = EdwardsAffine::new_unchecked(x, y);
        let ks = generate_keystream(&p, 1);
        let actual = {
            let mut bytes = ks[0].into_bigint().to_bytes_be();
            bytes.resize(32, 0);
            hex::encode(&bytes)
        };
        assert_eq!(
            actual, "1e05682c815341647510bf582454cca025584699f2419cbdea3205afb3506e5b",
            "Poseidon([shared.x=1, shared.y=2, counter=1]) drifted from the \
             pinned circomlib-compatible value; the Circom circuit will no \
             longer accept ciphertexts from this library"
        );
    }

    // ─── Domain-separated KEM-DEM tests ──────────────────────────

    fn test_domains() -> KemDemDomains {
        KemDemDomains {
            kem_domain: Fr254::from(0xABCD_u64),
            dem_domain: Fr254::from(0x1234_u64),
        }
    }

    #[test]
    fn domain_roundtrip_uncompressed() {
        let (sk, pk) = rand_keypair();
        let payload: Vec<Fr254> = (0..5).map(|i| Fr254::from(i as u64 * 100 + 7)).collect();
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct = zk_kemdem_encrypt_with_domains(seed, &pk, &payload, &domains, false).unwrap();
        assert_eq!(
            ct.len(),
            (payload.len() + EPHEM_ELEMS) * FR_BYTES * 2,
            "wire size must be (payload + 2 ephem) * 32 bytes * 2 hex chars"
        );
        let pt = zk_kemdem_decrypt_with_domains(&sk, &ct, &domains, false).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn domain_roundtrip_compressed() {
        let (sk, pk) = rand_keypair();
        let payload: Vec<Fr254> = (0..5).map(|i| Fr254::from(i as u64 * 100 + 7)).collect();
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct = zk_kemdem_encrypt_with_domains(seed, &pk, &payload, &domains, true).unwrap();
        assert_eq!(
            ct.len(),
            (payload.len() + EPHEM_ELEMS) * FR_BYTES * 2,
            "compressed EPK still uses 2 trailing elements"
        );
        let pt = zk_kemdem_decrypt_with_domains(&sk, &ct, &domains, true).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn domain_wrong_key_does_not_recover() {
        let mut rng = ark_std::test_rng();
        let (_, pk) = rand_keypair_with(&mut rng);
        let (other_sk, _) = rand_keypair_with(&mut rng);
        let payload = vec![Fr254::from(0xdeadbeefu64), Fr254::from(0xfeedf00du64)];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut rng, &mut seed);

        let domains = test_domains();
        let ct = zk_kemdem_encrypt_with_domains(seed, &pk, &payload, &domains, false).unwrap();
        let wrong = zk_kemdem_decrypt_with_domains(&other_sk, &ct, &domains, false).unwrap();
        assert_ne!(wrong, payload);
    }

    #[test]
    fn domain_wrong_domains_does_not_recover() {
        let (sk, pk) = rand_keypair();
        let payload = vec![Fr254::from(42u64)];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct = zk_kemdem_encrypt_with_domains(seed, &pk, &payload, &domains, false).unwrap();

        // Decrypt with different domain constants
        let wrong_domains = KemDemDomains {
            kem_domain: Fr254::from(0xFFFF_u64),
            dem_domain: Fr254::from(0x5678_u64),
        };
        let wrong = zk_kemdem_decrypt_with_domains(&sk, &ct, &wrong_domains, false).unwrap();
        assert_ne!(
            wrong, payload,
            "mismatched domains must not recover plaintext"
        );
    }

    #[test]
    fn domain_encrypt_zero_seed_returns_retry() {
        use ark_ec::PrimeGroup;
        let pk: EdwardsAffine = EdwardsProjective::generator().into_affine();
        let payload = vec![Fr254::from(1u64)];
        let domains = test_domains();
        let err =
            zk_kemdem_encrypt_with_domains([0u8; 32], &pk, &payload, &domains, false).unwrap_err();
        assert_eq!(err, ZkKemDemError::RetryNeeded);
    }

    #[test]
    fn domain_decrypt_rejects_oversized_payload() {
        // Fabricate a ciphertext with (MAX_PAYLOAD_ELEMS + 1) + 2 elements.
        let element_count = MAX_PAYLOAD_ELEMS + 1 + EPHEM_ELEMS;
        let bytes = vec![0u8; element_count * FR_BYTES];
        let hex = hex::encode(&bytes);
        let sk = BabyJubJubScalar::from(42u64);
        let domains = test_domains();
        let err = zk_kemdem_decrypt_with_domains(&sk, &hex, &domains, false).unwrap_err();
        match err {
            ZkKemDemError::PayloadTooLarge { .. } => {}
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    /// Pinned test vector for the two-level keystream. If this breaks,
    /// the domain-separated derivation formula changed — any protocol
    /// circuit using this keystream will no longer accept ciphertexts
    /// from this library.
    #[test]
    fn domain_keystream_pinned_vector() {
        let x = Fr254::from(1u64);
        let y = Fr254::from(2u64);
        let p = EdwardsAffine::new_unchecked(x, y);
        let domains = KemDemDomains {
            kem_domain: Fr254::from(100u64),
            dem_domain: Fr254::from(200u64),
        };
        let ks = generate_keystream_with_domains(&p, 1, &domains);
        let actual = {
            let mut bytes = ks[0].into_bigint().to_bytes_be();
            bytes.resize(32, 0);
            hex::encode(&bytes)
        };
        assert_eq!(
            actual,
            "2c47b543aad579cc0e63cbe2b3b249cb220bb66f34cd25c960ddba4e674f8ae4",
            "domain keystream drifted from pinned value; any protocol circuit using \
             this keystream will no longer accept ciphertexts from this library"
        );

        let ks2 = generate_keystream_with_domains(&p, 1, &domains);
        assert_eq!(ks, ks2, "domain keystream must be deterministic");
    }

    #[test]
    fn domain_keystream_differs_from_standard() {
        let (_, pk) = rand_keypair();
        let standard = generate_keystream(&pk, 3);
        let domains = test_domains();
        let domain_ks = generate_keystream_with_domains(&pk, 3, &domains);
        assert_ne!(
            standard, domain_ks,
            "domain-separated keystream must differ from the standard one"
        );
    }

    // ─── Authenticated domain-separated KEM-DEM tests ────────────

    #[test]
    fn domain_authenticated_roundtrip_uncompressed() {
        let (sk, pk) = rand_keypair();
        let payload: Vec<Fr254> = (0..5).map(|i| Fr254::from(i as u64 * 100 + 7)).collect();
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct = zk_kemdem_encrypt_authenticated_with_domains(seed, &pk, &payload, &domains, false)
            .unwrap();
        let pt = zk_kemdem_decrypt_authenticated_with_domains(&sk, &ct, &domains, false).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn domain_authenticated_roundtrip_compressed() {
        let (sk, pk) = rand_keypair();
        let payload: Vec<Fr254> = (0..5).map(|i| Fr254::from(i as u64 * 100 + 7)).collect();
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct = zk_kemdem_encrypt_authenticated_with_domains(seed, &pk, &payload, &domains, true)
            .unwrap();
        let pt = zk_kemdem_decrypt_authenticated_with_domains(&sk, &ct, &domains, true).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn domain_authenticated_rejects_flipped_bit() {
        let (sk, pk) = rand_keypair();
        let payload = vec![Fr254::from(0xdeadbeefu64), Fr254::from(0xfeedf00du64)];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct_hex =
            zk_kemdem_encrypt_authenticated_with_domains(seed, &pk, &payload, &domains, false)
                .unwrap();
        let mut bytes = hex::decode(&ct_hex).unwrap();
        bytes[0] ^= 0x01;
        let tampered_hex = hex::encode(&bytes);

        let err = zk_kemdem_decrypt_authenticated_with_domains(&sk, &tampered_hex, &domains, false)
            .unwrap_err();
        assert_eq!(err, ZkKemDemError::MacMismatch);
    }

    #[test]
    fn domain_authenticated_rejects_swapped_epk() {
        let (sk, pk) = rand_keypair();
        let payload = vec![Fr254::from(1u64), Fr254::from(2u64)];

        let domains = test_domains();
        let ct1 = zk_kemdem_encrypt_authenticated_with_domains(
            [30u8; 32], &pk, &payload, &domains, false,
        )
        .unwrap();
        let ct2 = zk_kemdem_encrypt_authenticated_with_domains(
            [31u8; 32], &pk, &payload, &domains, false,
        )
        .unwrap();

        let ct1_bytes = hex::decode(&ct1).unwrap();
        let ct2_bytes = hex::decode(&ct2).unwrap();
        let body_len = 2 * FR_BYTES;
        // Splice: ct1 body + ct2 EPK + ct1 tag
        let mut spliced = ct1_bytes[..body_len].to_vec();
        spliced.extend_from_slice(&ct2_bytes[body_len..body_len + 2 * FR_BYTES]);
        spliced.extend_from_slice(&ct1_bytes[body_len + 2 * FR_BYTES..]);
        let spliced_hex = hex::encode(&spliced);

        let err = zk_kemdem_decrypt_authenticated_with_domains(&sk, &spliced_hex, &domains, false)
            .unwrap_err();
        assert_eq!(err, ZkKemDemError::MacMismatch);
    }

    #[test]
    fn domain_authenticated_rejects_unauthenticated_ciphertext() {
        let (sk, pk) = rand_keypair();
        let payload = vec![Fr254::from(42u64), Fr254::from(99u64)];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let unauth_ct =
            zk_kemdem_encrypt_with_domains(seed, &pk, &payload, &domains, false).unwrap();
        let result = zk_kemdem_decrypt_authenticated_with_domains(&sk, &unauth_ct, &domains, false);
        assert!(
            result.is_err(),
            "authenticated decrypt must reject an unauthenticated ciphertext"
        );
    }

    #[test]
    fn domain_decrypt_rejects_bad_sign_flag_compressed() {
        let (sk, pk) = rand_keypair();
        let payload = vec![Fr254::from(42u64)];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct_hex =
            zk_kemdem_encrypt_with_domains(seed, &pk, &payload, &domains, true).unwrap();
        let mut ct_bytes = hex::decode(&ct_hex).unwrap();

        let sign_flag_offset = (payload.len()) * FR_BYTES + FR_BYTES;
        ct_bytes[sign_flag_offset] = 0x42;

        let bad_hex = hex::encode(&ct_bytes);
        let err = zk_kemdem_decrypt_with_domains(&sk, &bad_hex, &domains, true).unwrap_err();
        assert_eq!(err, ZkKemDemError::InvalidEphemeralPoint("compressed sign flag must be 0 or 1"));
    }

    #[test]
    fn domain_authenticated_wire_size() {
        let (_, pk) = rand_keypair();
        let payload = vec![Fr254::from(1u64); 4];
        let mut seed = [0u8; 32];
        ark_std::rand::RngCore::fill_bytes(&mut ark_std::test_rng(), &mut seed);

        let domains = test_domains();
        let ct = zk_kemdem_encrypt_authenticated_with_domains(seed, &pk, &payload, &domains, false)
            .unwrap();
        assert_eq!(
            ct.len(),
            (payload.len() + EPHEM_AND_TAG_ELEMS) * FR_BYTES * 2,
            "authenticated wire size must be (payload + 2 epk + 1 tag) * 32 * 2"
        );
    }
}
