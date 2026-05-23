//! WASM-facing ZK-friendly encryption (`ZkEncryptor`) over the
//! BabyJubJub KEM-DEM primitives in [`crate::kemdem_functions`].

use wasm_bindgen::prelude::*;

use crate::hex_util::{
    fill_random, fr_to_be_hex, js_err, parse_babyjubjub_scalar_be, parse_fr_be,
};

/// ZK-friendly encryptor using a BabyJubJub KEM-DEM over the BN254
/// scalar field `Fr`.
///
/// The keystream PRF is the iden3 `circomlib`-compatible Poseidon
/// hash (`PoseidonEx(t=4)`), so the produced ciphertexts can be
/// verified inside a Circom circuit using `circomlib`'s `Poseidon(3)`
/// and `EscalarMulAny` templates with byte-for-byte agreement.
///
/// **`encrypt`/`decrypt` provide confidentiality only.** Wrap with a
/// Poseidon-based MAC if you need integrity, or — preferred — use
/// `encryptAuthenticated`/`decryptAuthenticated`.
#[wasm_bindgen]
pub struct ZkEncryptor;

#[wasm_bindgen]
impl ZkEncryptor {
    /// Encrypt a payload of `Fr` elements to a BabyJubJub public key.
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(
        receiver_pub_x_hex: &str,
        receiver_pub_y_hex: &str,
        payload_hex_array: Vec<String>,
    ) -> Result<String, JsValue> {
        use crate::kemdem_functions::{point_from_xy, zk_kemdem_encrypt, ZkKemDemError};

        let x = parse_fr_be(receiver_pub_x_hex).map_err(js_err)?;
        let y = parse_fr_be(receiver_pub_y_hex).map_err(js_err)?;
        let receiver_pub = point_from_xy(x, y).ok_or_else(|| {
            js_err(
                "receiver public key is invalid: identity, off-curve, or wrong subgroup",
            )
        })?;

        let mut payload = Vec::with_capacity(payload_hex_array.len());
        for s in payload_hex_array {
            payload.push(parse_fr_be(&s).map_err(js_err)?);
        }

        // Retry loop: probability of zero scalar is ≈ 2⁻²⁵¹. Cap the
        // number of attempts so a pathological RNG (test stub, broken
        // entropy source) fails loudly instead of spinning forever.
        const MAX_RETRIES: u32 = 8;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match zk_kemdem_encrypt(seed, &receiver_pub, &payload) {
                Ok(ct) => return Ok(ct),
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        Err(js_err(
            "CSPRNG produced zero scalar repeatedly; system entropy may be broken",
        ))
    }

    /// **Authenticated** counterpart of [`encrypt`]. Emits a
    /// ciphertext that includes a Poseidon MAC tag bound to the
    /// shared secret and the ephemeral public key.
    #[wasm_bindgen(js_name = encryptAuthenticated)]
    pub fn encrypt_authenticated(
        receiver_pub_x_hex: &str,
        receiver_pub_y_hex: &str,
        payload_hex_array: Vec<String>,
    ) -> Result<String, JsValue> {
        use crate::kemdem_functions::{
            point_from_xy, zk_kemdem_encrypt_authenticated, ZkKemDemError,
        };

        let x = parse_fr_be(receiver_pub_x_hex).map_err(js_err)?;
        let y = parse_fr_be(receiver_pub_y_hex).map_err(js_err)?;
        let receiver_pub = point_from_xy(x, y).ok_or_else(|| {
            js_err("receiver public key is invalid: identity, off-curve, or wrong subgroup")
        })?;

        let mut payload = Vec::with_capacity(payload_hex_array.len());
        for s in payload_hex_array {
            payload.push(parse_fr_be(&s).map_err(js_err)?);
        }

        const MAX_RETRIES: u32 = 8;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match zk_kemdem_encrypt_authenticated(seed, &receiver_pub, &payload) {
                Ok(ct) => return Ok(ct),
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        Err(js_err(
            "CSPRNG produced zero scalar repeatedly; system entropy may be broken",
        ))
    }

    /// **Authenticated** counterpart of [`decrypt`]. Verifies the
    /// Poseidon MAC tag before decrypting; throws if the ciphertext
    /// was tampered with or the wrong key was used.
    #[wasm_bindgen(js_name = decryptAuthenticated)]
    pub fn decrypt_authenticated(
        receiver_sec_key_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<js_sys::Array, JsValue> {
        use crate::kemdem_functions::zk_kemdem_decrypt_authenticated;
        use ark_ff::Zero;

        let sec_key = parse_babyjubjub_scalar_be(receiver_sec_key_hex).map_err(js_err)?;
        if sec_key.is_zero() {
            return Err(js_err("invalid secret key"));
        }

        let decrypted = zk_kemdem_decrypt_authenticated(&sec_key, ciphertext_hex)
            .map_err(|e| js_err(e.to_string()))?;

        let arr = js_sys::Array::new();
        for el in decrypted {
            arr.push(&JsValue::from_str(&fr_to_be_hex(&el)));
        }
        Ok(arr)
    }

    /// Decrypt a ciphertext produced by [`encrypt`].
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(
        receiver_sec_key_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<js_sys::Array, JsValue> {
        use crate::kemdem_functions::zk_kemdem_decrypt;
        use ark_ff::Zero;

        let sec_key = parse_babyjubjub_scalar_be(receiver_sec_key_hex).map_err(js_err)?;
        if sec_key.is_zero() {
            return Err(js_err("invalid secret key"));
        }

        let decrypted =
            zk_kemdem_decrypt(&sec_key, ciphertext_hex).map_err(|e| js_err(e.to_string()))?;

        let arr = js_sys::Array::new();
        for el in decrypted {
            arr.push(&JsValue::from_str(&fr_to_be_hex(&el)));
        }
        Ok(arr)
    }

    /// Generate a random BabyJubJub keypair.
    #[wasm_bindgen(js_name = generateKeypair)]
    pub fn generate_keypair() -> Result<js_sys::Object, JsValue> {
        use crate::kemdem_functions::{generate_keypair_from_seed, ZkKemDemError};
        use ark_ff::{BigInteger, PrimeField};

        const MAX_RETRIES: u32 = 8;
        let mut pair = None;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match generate_keypair_from_seed(seed) {
                Ok(p) => {
                    pair = Some(p);
                    break;
                }
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        let (sk, pk) = pair.ok_or_else(|| {
            js_err("CSPRNG produced zero scalar repeatedly; system entropy may be broken")
        })?;

        // BabyJubJub scalar field is 251 bits → `to_bytes_be` always
        // fits in 32 bytes; just left-pad to a fixed width.
        let be = sk.into_bigint().to_bytes_be();
        debug_assert!(be.len() <= 32, "BabyJubJub scalar must encode in ≤ 32 bytes");
        let mut sk_bytes = vec![0u8; 32];
        sk_bytes[32 - be.len()..].copy_from_slice(&be);

        if !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
            return Err(js_err("generated BabyJubJub public key failed validation"));
        }

        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("secretKey"),
            &JsValue::from_str(&format!("0x{}", hex::encode(&sk_bytes))),
        )
        .unwrap();

        let pub_obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &pub_obj,
            &JsValue::from_str("x"),
            &JsValue::from_str(&fr_to_be_hex(&pk.x)),
        )
        .unwrap();
        js_sys::Reflect::set(
            &pub_obj,
            &JsValue::from_str("y"),
            &JsValue::from_str(&fr_to_be_hex(&pk.y)),
        )
        .unwrap();
        js_sys::Reflect::set(&obj, &JsValue::from_str("publicKey"), &pub_obj).unwrap();

        Ok(obj)
    }
}

// ── Native tests for the ZK API surface ────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zk_generated_keypair_is_valid_and_roundtrips() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt, zk_kemdem_encrypt,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([7u8; 32]).unwrap();
        assert!(pk.is_on_curve());
        assert!(pk.is_in_correct_subgroup_assuming_on_curve());

        let payload = vec![Fr254::from(0xdeadbeefu64), Fr254::from(0xfeedf00du64)];
        let ct = zk_kemdem_encrypt([3u8; 32], &pk, &payload).unwrap();
        let pt = zk_kemdem_decrypt(&sk, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn zk_keypair_zero_seed_returns_retry() {
        use crate::kemdem_functions::{generate_keypair_from_seed, ZkKemDemError};
        let err = generate_keypair_from_seed([0u8; 32]).unwrap_err();
        assert_eq!(err, ZkKemDemError::RetryNeeded);
    }

    #[test]
    fn authenticated_roundtrip() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_authenticated,
            zk_kemdem_encrypt_authenticated,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([5u8; 32]).unwrap();
        let payload: Vec<Fr254> = (0..5).map(|i| Fr254::from(i as u64 * 7 + 1)).collect();

        let ct = zk_kemdem_encrypt_authenticated([6u8; 32], &pk, &payload).unwrap();
        let pt = zk_kemdem_decrypt_authenticated(&sk, &ct).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn authenticated_rejects_flipped_ciphertext_bit() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_authenticated,
            zk_kemdem_encrypt_authenticated, ZkKemDemError,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([9u8; 32]).unwrap();
        let payload = vec![Fr254::from(0xdeadbeefu64), Fr254::from(0xfeedf00du64)];

        let ct_hex = zk_kemdem_encrypt_authenticated([10u8; 32], &pk, &payload).unwrap();
        let mut bytes = hex::decode(&ct_hex).unwrap();
        bytes[0] ^= 0x01;
        let tampered_hex = hex::encode(&bytes);

        let err = zk_kemdem_decrypt_authenticated(&sk, &tampered_hex).unwrap_err();
        assert_eq!(err, ZkKemDemError::MacMismatch);
    }

    #[test]
    fn authenticated_rejects_swapped_ephemeral_key() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_authenticated,
            zk_kemdem_encrypt_authenticated, ZkKemDemError, FR_BYTES,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([11u8; 32]).unwrap();
        let payload = vec![Fr254::from(1u64), Fr254::from(2u64)];

        let ct1 = zk_kemdem_encrypt_authenticated([12u8; 32], &pk, &payload).unwrap();
        let ct2 = zk_kemdem_encrypt_authenticated([13u8; 32], &pk, &payload).unwrap();

        let ct1_bytes = hex::decode(&ct1).unwrap();
        let ct2_bytes = hex::decode(&ct2).unwrap();
        let body_len = 2 * FR_BYTES;
        let mut spliced = ct1_bytes[..body_len].to_vec();
        spliced.extend_from_slice(&ct2_bytes[body_len..body_len + 2 * FR_BYTES]);
        spliced.extend_from_slice(&ct1_bytes[body_len + 2 * FR_BYTES..]);
        let spliced_hex = hex::encode(&spliced);

        let err = zk_kemdem_decrypt_authenticated(&sk, &spliced_hex).unwrap_err();
        assert_eq!(err, ZkKemDemError::MacMismatch);
    }

    #[test]
    fn authenticated_rejects_unauthenticated_ciphertext() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_authenticated, zk_kemdem_encrypt,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([14u8; 32]).unwrap();
        let payload = vec![Fr254::from(42u64), Fr254::from(99u64)];

        let unauth_ct = zk_kemdem_encrypt([15u8; 32], &pk, &payload).unwrap();
        let result = zk_kemdem_decrypt_authenticated(&sk, &unauth_ct);
        assert!(
            result.is_err(),
            "authenticated decrypt must reject an unauthenticated ciphertext"
        );
    }

    #[test]
    fn authenticated_wire_size() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_encrypt_authenticated, EPHEM_AND_TAG_ELEMS,
            FR_BYTES,
        };
        use ark_bn254::Fr as Fr254;

        let (_, pk) = generate_keypair_from_seed([17u8; 32]).unwrap();
        let payload = vec![Fr254::from(1u64); 4];
        let ct = zk_kemdem_encrypt_authenticated([18u8; 32], &pk, &payload).unwrap();
        assert_eq!(ct.len(), (payload.len() + EPHEM_AND_TAG_ELEMS) * FR_BYTES * 2);
    }

    #[test]
    fn zk_encrypt_payload_too_large_is_typed_error() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_encrypt, MAX_PAYLOAD_ELEMS, ZkKemDemError,
        };
        use ark_bn254::Fr as Fr254;

        let (_, pk) = generate_keypair_from_seed([1u8; 32]).unwrap();
        let payload = vec![Fr254::from(1u64); MAX_PAYLOAD_ELEMS + 1];
        let seed = [2u8; 32];
        let err = zk_kemdem_encrypt(seed, &pk, &payload).unwrap_err();
        match err {
            ZkKemDemError::PayloadTooLarge { len, max } => {
                assert_eq!(len, MAX_PAYLOAD_ELEMS + 1);
                assert_eq!(max, MAX_PAYLOAD_ELEMS);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn zk_encrypt_zero_seed_is_retry_needed() {
        use crate::kemdem_functions::{zk_kemdem_encrypt, ZkKemDemError};
        use ark_bn254::Fr as Fr254;
        use ark_ec::{CurveGroup, PrimeGroup};
        use taceo_ark_babyjubjub::EdwardsAffine;
        use taceo_ark_babyjubjub::EdwardsProjective;

        let pk: EdwardsAffine = EdwardsProjective::generator().into_affine();
        let payload = vec![Fr254::from(1u64)];
        let zero_seed = [0u8; 32];
        let err = zk_kemdem_encrypt(zero_seed, &pk, &payload).unwrap_err();
        assert_eq!(err, ZkKemDemError::RetryNeeded);
    }

    #[test]
    fn point_from_xy_rejects_identity() {
        use crate::kemdem_functions::point_from_xy;
        use ark_bn254::Fr as Fr254;
        use ark_ff::{One, Zero};

        let id = point_from_xy(Fr254::zero(), Fr254::one());
        assert!(id.is_none(), "identity must be rejected by point_from_xy");

        let zz = point_from_xy(Fr254::zero(), Fr254::zero());
        assert!(zz.is_none(), "(0,0) must be rejected");
    }

    #[test]
    fn decrypt_rejects_identity_ephemeral() {
        use crate::kemdem_functions::{zk_kemdem_decrypt, ZkKemDemError, FR_BYTES};
        use ark_bn254::Fr as Fr254;
        use ark_ff::{BigInteger, One, PrimeField, Zero};

        let one_byte_le = {
            let mut b = Fr254::one().into_bigint().to_bytes_le();
            b.resize(FR_BYTES, 0);
            b
        };
        let zero_byte_le = {
            let mut b = Fr254::zero().into_bigint().to_bytes_le();
            b.resize(FR_BYTES, 0);
            b
        };
        let mut bytes = vec![0u8; FR_BYTES];
        bytes.extend_from_slice(&zero_byte_le);
        bytes.extend_from_slice(&one_byte_le);
        let hex = hex::encode(&bytes);

        use taceo_ark_babyjubjub::Fr as BabyJubJubScalar;
        let sk = BabyJubJubScalar::from(42u64);
        let err = zk_kemdem_decrypt(&sk, &hex).unwrap_err();
        match err {
            ZkKemDemError::InvalidEphemeralPoint("identity point") => {}
            other => panic!("expected InvalidEphemeralPoint(\"identity point\"), got {other:?}"),
        }
    }
}
