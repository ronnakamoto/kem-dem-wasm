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
use ark_ff::{BigInteger, PrimeField, Zero};
use light_poseidon::{Poseidon, PoseidonHasher};
use std::ops::Add;
use taceo_ark_babyjubjub::{EdwardsAffine, EdwardsProjective, Fr as BabyJubJubScalar};

/// Number of bytes per Fr element on the wire.
pub const FR_BYTES: usize = 32;
/// Number of trailing Fr elements that encode the ephemeral public key.
pub const EPHEM_ELEMS: usize = 2;

/// Encrypt `payload` (a slice of Fr elements) to `receiver_pub_key`.
///
/// `random_seed` is interpreted as a uniform 32-byte sample and reduced
/// mod the BabyJubJub scalar field to produce the ephemeral scalar `r`.
/// Callers MUST sample `random_seed` from a CSPRNG and never reuse it.
///
/// Returns a hex-encoded ciphertext.
pub fn zk_kemdem_encrypt(
    random_seed: [u8; 32],
    receiver_pub_key: &EdwardsAffine,
    payload: &[Fr254],
) -> String {
    let mut r = BabyJubJubScalar::from_le_bytes_mod_order(&random_seed);
    if r.is_zero() {
        r = BabyJubJubScalar::from(1u64);
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

    encode_elements_le_hex(&elements)
}

/// Decrypt a hex-encoded ciphertext using `receiver_sec_key`.
pub fn zk_kemdem_decrypt(
    receiver_sec_key: &BabyJubJubScalar,
    ciphertext_hex: &str,
) -> Result<Vec<Fr254>, String> {
    let elements = decode_elements_le_hex(ciphertext_hex)?;

    if elements.len() < EPHEM_ELEMS {
        return Err("ciphertext too short: missing ephemeral public key".to_string());
    }
    let payload_len = elements.len() - EPHEM_ELEMS;

    let ephem_x = elements[payload_len];
    let ephem_y = elements[payload_len + 1];
    if ephem_x.is_zero() && ephem_y.is_zero() {
        return Err("invalid ephemeral public key: identity".to_string());
    }
    let ephemeral_pub = EdwardsAffine::new_unchecked(ephem_x, ephem_y);
    if !ephemeral_pub.is_on_curve() {
        return Err("invalid ephemeral public key: not on BabyJubJub".to_string());
    }
    if !ephemeral_pub.is_in_correct_subgroup_assuming_on_curve() {
        return Err("invalid ephemeral public key: wrong subgroup".to_string());
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

fn encode_elements_le_hex(elements: &[Fr254]) -> String {
    let mut bytes = Vec::with_capacity(elements.len() * FR_BYTES);
    for el in elements {
        let mut le = el.into_bigint().to_bytes_le();
        le.resize(FR_BYTES, 0);
        bytes.extend_from_slice(&le);
    }
    hex::encode(&bytes)
}

fn decode_elements_le_hex(ciphertext_hex: &str) -> Result<Vec<Fr254>, String> {
    let bytes = hex::decode(ciphertext_hex.trim_start_matches("0x"))
        .map_err(|e| format!("invalid ciphertext hex: {e}"))?;
    if bytes.len() % FR_BYTES != 0 {
        return Err(format!(
            "ciphertext length {} is not a multiple of {FR_BYTES}",
            bytes.len()
        ));
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
pub fn generate_keypair_from_seed(seed: [u8; 32]) -> (BabyJubJubScalar, EdwardsAffine) {
    let mut sk = BabyJubJubScalar::from_le_bytes_mod_order(&seed);
    if sk.is_zero() {
        sk = BabyJubJubScalar::from(1u64);
    }
    let pk = (EdwardsProjective::generator() * sk).into_affine();
    (sk, pk)
}

/// Reconstruct an `EdwardsAffine` from its raw `(x, y)` Fr254 coordinates
/// and verify it lies on the BabyJubJub curve and in the prime-order
/// subgroup. Returns `None` for any invalid input.
pub fn point_from_xy(x: Fr254, y: Fr254) -> Option<EdwardsAffine> {
    if x.is_zero() && y.is_zero() {
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

        let ct = zk_kemdem_encrypt(seed, &pk, &payload);
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

        let ct = zk_kemdem_encrypt(seed, &pk, &payload);
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

        let ct = zk_kemdem_encrypt(seed, &pk, &payload);
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
}
