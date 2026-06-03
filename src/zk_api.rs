//! WASM-facing ZK-friendly encryption (`ZkEncryptor`) over the
//! BabyJubJub KEM-DEM primitives in [`crate::kemdem_functions`].

use wasm_bindgen::prelude::*;

use crate::hex_util::{
    fill_random, fr_to_be_hex, js_err, parse_babyjubjub_scalar_be, parse_fr_be, parse_fr_be_labeled,
};

/// Parse a 0x-prefixed big-endian hex secret key into the 32-byte
/// little-endian buffer the curve-generic dispatcher expects.
///
/// The string must decode to exactly 32 bytes; any other length is a
/// hard error. The returned bytes are a verbatim BE→LE reverse of
/// the input, so for callers using the default curve this is the
/// canonical encoding of the secret scalar mod the BabyJubJub
/// scalar field. For custom curves, the runtime backend treats the
/// bytes as a 256-bit unsigned integer (see `runtime_kemdem`'s
/// docs).
///
/// All-zero buffers are rejected up-front so the JS facade emits a
/// uniform `"invalid secret key"` message for the obvious mistake of
/// passing an empty / placeholder key; non-trivial near-zero values
/// that happen to reduce to zero on a given curve are caught later
/// by the dispatcher's `RetryNeeded` arm.
fn parse_secret_key_to_le32(hex_be: &str) -> Result<[u8; 32], JsValue> {
    let stripped = hex_be.trim_start_matches("0x");
    let bytes = hex::decode(stripped)
        .map_err(|e| js_err(format!("invalid secret key hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(js_err(format!(
            "invalid secret key length: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    if bytes.iter().all(|&b| b == 0) {
        return Err(js_err("invalid secret key"));
    }
    let mut le = [0u8; 32];
    // Input is big-endian; reverse to little-endian.
    for (i, b) in bytes.iter().enumerate() {
        le[31 - i] = *b;
    }
    Ok(le)
}

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
            js_err("receiver public key is invalid: identity, off-curve, or wrong subgroup")
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

        let arr = js_sys::Array::new_with_length(decrypted.len() as u32);
        for (i, el) in decrypted.iter().enumerate() {
            arr.set(i as u32, JsValue::from_str(&fr_to_be_hex(el)));
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

        let arr = js_sys::Array::new_with_length(decrypted.len() as u32);
        for (i, el) in decrypted.iter().enumerate() {
            arr.set(i as u32, JsValue::from_str(&fr_to_be_hex(el)));
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
        debug_assert!(
            be.len() <= 32,
            "BabyJubJub scalar must encode in ≤ 32 bytes"
        );
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

    /// Encrypt a payload using a two-level KEM-DEM with caller-supplied
    /// Poseidon domain separators.
    ///
    /// Parameters:
    ///   `receiver_pub_x_hex` / `receiver_pub_y_hex`
    ///       BabyJubJub public key of the recipient (0x-prefixed BE hex Fr254).
    ///   `payload_hex_array`
    ///       Array of Fr254 values to encrypt (0x-prefixed BE hex strings).
    ///   `kem_domain_hex` / `dem_domain_hex`
    ///       Protocol-specific domain constants (0x-prefixed BE hex Fr254).
    ///       These provide cryptographic separation between the KEM and DEM
    ///       layers and between different protocols sharing the same key
    ///       material.
    ///   `compress_epk`
    ///       `true`  → EPK stored as `[epk_y, sign_flag]` (compressed).
    ///       `false` → EPK stored as `[epk_x, epk_y]`     (uncompressed).
    ///
    /// **Confidentiality only.** For integrity protection, use
    /// [`encryptAuthenticatedWithDomains`].
    ///
    /// Returns a lowercase hex string of `(payload.len() + 2) * 64` characters.
    #[wasm_bindgen(js_name = encryptWithDomains)]
    pub fn encrypt_with_domains(
        receiver_pub_x_hex: &str,
        receiver_pub_y_hex: &str,
        payload_hex_array: Vec<String>,
        kem_domain_hex: &str,
        dem_domain_hex: &str,
        compress_epk: bool,
    ) -> Result<String, JsValue> {
        use crate::kemdem_functions::{
            point_from_xy, zk_kemdem_encrypt_with_domains, KemDemDomains, ZkKemDemError,
        };

        let x = parse_fr_be(receiver_pub_x_hex).map_err(js_err)?;
        let y = parse_fr_be(receiver_pub_y_hex).map_err(js_err)?;
        let kem_domain = parse_fr_be_labeled(kem_domain_hex, "kem_domain").map_err(js_err)?;
        let dem_domain = parse_fr_be_labeled(dem_domain_hex, "dem_domain").map_err(js_err)?;
        let receiver_pub = point_from_xy(x, y).ok_or_else(|| {
            js_err("receiver public key is invalid: identity, off-curve, or wrong subgroup")
        })?;

        let mut payload = Vec::with_capacity(payload_hex_array.len());
        for s in payload_hex_array {
            payload.push(parse_fr_be(&s).map_err(js_err)?);
        }

        let domains = KemDemDomains {
            kem_domain,
            dem_domain,
        };

        const MAX_RETRIES: u32 = 8;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match zk_kemdem_encrypt_with_domains(
                seed,
                &receiver_pub,
                &payload,
                &domains,
                compress_epk,
            ) {
                Ok(ct) => return Ok(ct),
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        Err(js_err(
            "CSPRNG produced zero scalar repeatedly; system entropy may be broken",
        ))
    }

    /// Decrypt a ciphertext produced by [`encryptWithDomains`].
    ///
    /// Parameters mirror [`encryptWithDomains`]; `compress_epk` must match
    /// the value used during encryption.
    ///
    /// Returns an array of BE hex Fr254 strings.
    #[wasm_bindgen(js_name = decryptWithDomains)]
    pub fn decrypt_with_domains(
        receiver_sec_key_hex: &str,
        ciphertext_hex: &str,
        kem_domain_hex: &str,
        dem_domain_hex: &str,
        compress_epk: bool,
    ) -> Result<js_sys::Array, JsValue> {
        use crate::kemdem_functions::{zk_kemdem_decrypt_with_domains, KemDemDomains};
        use ark_ff::Zero;

        let sec_key = parse_babyjubjub_scalar_be(receiver_sec_key_hex).map_err(js_err)?;
        let kem_domain = parse_fr_be_labeled(kem_domain_hex, "kem_domain").map_err(js_err)?;
        let dem_domain = parse_fr_be_labeled(dem_domain_hex, "dem_domain").map_err(js_err)?;
        if sec_key.is_zero() {
            return Err(js_err("invalid secret key"));
        }

        let domains = KemDemDomains {
            kem_domain,
            dem_domain,
        };

        let decrypted =
            zk_kemdem_decrypt_with_domains(&sec_key, ciphertext_hex, &domains, compress_epk)
                .map_err(|e| js_err(e.to_string()))?;

        let arr = js_sys::Array::new_with_length(decrypted.len() as u32);
        for (i, el) in decrypted.iter().enumerate() {
            arr.set(i as u32, JsValue::from_str(&fr_to_be_hex(el)));
        }
        Ok(arr)
    }

    /// **Authenticated** counterpart of [`encryptWithDomains`]. Emits a
    /// ciphertext that includes a Poseidon MAC tag derived from the
    /// domain-separated intermediate encryption key.
    ///
    /// Returns a lowercase hex string of `(payload.len() + 3) * 64` characters
    /// (2 extra elements for the EPK + 1 for the MAC tag).
    #[wasm_bindgen(js_name = encryptAuthenticatedWithDomains)]
    pub fn encrypt_authenticated_with_domains(
        receiver_pub_x_hex: &str,
        receiver_pub_y_hex: &str,
        payload_hex_array: Vec<String>,
        kem_domain_hex: &str,
        dem_domain_hex: &str,
        compress_epk: bool,
    ) -> Result<String, JsValue> {
        use crate::kemdem_functions::{
            point_from_xy, zk_kemdem_encrypt_authenticated_with_domains, KemDemDomains,
            ZkKemDemError,
        };

        let x = parse_fr_be(receiver_pub_x_hex).map_err(js_err)?;
        let y = parse_fr_be(receiver_pub_y_hex).map_err(js_err)?;
        let kem_domain = parse_fr_be_labeled(kem_domain_hex, "kem_domain").map_err(js_err)?;
        let dem_domain = parse_fr_be_labeled(dem_domain_hex, "dem_domain").map_err(js_err)?;
        let receiver_pub = point_from_xy(x, y).ok_or_else(|| {
            js_err("receiver public key is invalid: identity, off-curve, or wrong subgroup")
        })?;

        let mut payload = Vec::with_capacity(payload_hex_array.len());
        for s in payload_hex_array {
            payload.push(parse_fr_be(&s).map_err(js_err)?);
        }

        let domains = KemDemDomains {
            kem_domain,
            dem_domain,
        };

        const MAX_RETRIES: u32 = 8;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match zk_kemdem_encrypt_authenticated_with_domains(
                seed,
                &receiver_pub,
                &payload,
                &domains,
                compress_epk,
            ) {
                Ok(ct) => return Ok(ct),
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        Err(js_err(
            "CSPRNG produced zero scalar repeatedly; system entropy may be broken",
        ))
    }

    /// **Authenticated** counterpart of [`decryptWithDomains`]. Verifies
    /// the Poseidon MAC tag before decrypting; throws if the ciphertext
    /// was tampered with or the wrong key was used.
    ///
    /// `compress_epk` must match the value used during encryption.
    #[wasm_bindgen(js_name = decryptAuthenticatedWithDomains)]
    pub fn decrypt_authenticated_with_domains(
        receiver_sec_key_hex: &str,
        ciphertext_hex: &str,
        kem_domain_hex: &str,
        dem_domain_hex: &str,
        compress_epk: bool,
    ) -> Result<js_sys::Array, JsValue> {
        use crate::kemdem_functions::{
            zk_kemdem_decrypt_authenticated_with_domains, KemDemDomains,
        };
        use ark_ff::Zero;

        let sec_key = parse_babyjubjub_scalar_be(receiver_sec_key_hex).map_err(js_err)?;
        let kem_domain = parse_fr_be_labeled(kem_domain_hex, "kem_domain").map_err(js_err)?;
        let dem_domain = parse_fr_be_labeled(dem_domain_hex, "dem_domain").map_err(js_err)?;
        if sec_key.is_zero() {
            return Err(js_err("invalid secret key"));
        }

        let domains = KemDemDomains {
            kem_domain,
            dem_domain,
        };

        let decrypted = zk_kemdem_decrypt_authenticated_with_domains(
            &sec_key,
            ciphertext_hex,
            &domains,
            compress_epk,
        )
        .map_err(|e| js_err(e.to_string()))?;

        let arr = js_sys::Array::new_with_length(decrypted.len() as u32);
        for (i, el) in decrypted.iter().enumerate() {
            arr.set(i as u32, JsValue::from_str(&fr_to_be_hex(el)));
        }
        Ok(arr)
    }
}

// ── Curve-generic dispatcher methods ─────────────────────────────
//
// Each `*On(curve, ...)` method takes an explicit `&ZkCurve` and
// routes to `crate::kemdem_functions::*_on`. The legacy methods
// above stay unchanged: they implicitly use the built-in default
// curve, so previously-deployed callers see byte-identical output.
//
// The default curve continues to use the audited typed
// `taceo-ark-babyjubjub` arithmetic; any other curve constructed via
// `ZkCurve.newValidated(...)` is routed through the curve-generic
// runtime arithmetic backend in `crate::te_arith`. Cross-backend
// byte-equivalence on the default curve is asserted by the
// `cross_backend_*` goldens in `crate::kemdem_functions::tests`.

#[wasm_bindgen]
impl ZkEncryptor {
    /// Generate a BabyJubJub keypair on the supplied curve, seeded by
    /// the OS CSPRNG. Returns `{ secretKey, publicKey: { x, y } }`.
    #[wasm_bindgen(js_name = generateKeypairOn)]
    pub fn generate_keypair_on(curve: &crate::curve::ZkCurve) -> Result<js_sys::Object, JsValue> {
        use crate::kemdem_functions::{generate_keypair_from_seed_on, ZkKemDemError};

        const MAX_RETRIES: u32 = 8;
        let mut tuple = None;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match generate_keypair_from_seed_on(curve.curve(), seed) {
                Ok(t) => {
                    tuple = Some(t);
                    break;
                }
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        let (sk_le, pk_x, pk_y) = tuple.ok_or_else(|| {
            js_err("CSPRNG produced zero scalar repeatedly; system entropy may be broken")
        })?;

        // The dispatcher returns the secret in canonical little-endian
        // form (32 bytes). Surface it on the JS side as 0x-prefixed
        // big-endian hex, matching the `secretKey` formatting used
        // everywhere else in the API.
        let mut sk_be = sk_le;
        sk_be.reverse();

        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("secretKey"),
            &JsValue::from_str(&format!("0x{}", hex::encode(sk_be))),
        )
        .unwrap();
        let pub_obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &pub_obj,
            &JsValue::from_str("x"),
            &JsValue::from_str(&fr_to_be_hex(&pk_x)),
        )
        .unwrap();
        js_sys::Reflect::set(
            &pub_obj,
            &JsValue::from_str("y"),
            &JsValue::from_str(&fr_to_be_hex(&pk_y)),
        )
        .unwrap();
        js_sys::Reflect::set(&obj, &JsValue::from_str("publicKey"), &pub_obj).unwrap();
        Ok(obj)
    }

    /// Curve-generic counterpart of [`encrypt`].
    #[wasm_bindgen(js_name = encryptOn)]
    pub fn encrypt_on(
        curve: &crate::curve::ZkCurve,
        receiver_pub_x_hex: &str,
        receiver_pub_y_hex: &str,
        payload_hex_array: Vec<String>,
    ) -> Result<String, JsValue> {
        use crate::kemdem_functions::{zk_kemdem_encrypt_on, ZkKemDemError};

        let x = parse_fr_be(receiver_pub_x_hex).map_err(js_err)?;
        let y = parse_fr_be(receiver_pub_y_hex).map_err(js_err)?;
        let mut payload = Vec::with_capacity(payload_hex_array.len());
        for s in payload_hex_array {
            payload.push(parse_fr_be(&s).map_err(js_err)?);
        }

        const MAX_RETRIES: u32 = 8;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match zk_kemdem_encrypt_on(curve.curve(), seed, x, y, &payload) {
                Ok(ct) => return Ok(ct),
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        Err(js_err(
            "CSPRNG produced zero scalar repeatedly; system entropy may be broken",
        ))
    }

    /// Curve-generic counterpart of [`encryptAuthenticated`].
    #[wasm_bindgen(js_name = encryptAuthenticatedOn)]
    pub fn encrypt_authenticated_on(
        curve: &crate::curve::ZkCurve,
        receiver_pub_x_hex: &str,
        receiver_pub_y_hex: &str,
        payload_hex_array: Vec<String>,
    ) -> Result<String, JsValue> {
        use crate::kemdem_functions::{zk_kemdem_encrypt_authenticated_on, ZkKemDemError};

        let x = parse_fr_be(receiver_pub_x_hex).map_err(js_err)?;
        let y = parse_fr_be(receiver_pub_y_hex).map_err(js_err)?;
        let mut payload = Vec::with_capacity(payload_hex_array.len());
        for s in payload_hex_array {
            payload.push(parse_fr_be(&s).map_err(js_err)?);
        }

        const MAX_RETRIES: u32 = 8;
        for _ in 0..MAX_RETRIES {
            let mut seed = [0u8; 32];
            fill_random(&mut seed);
            match zk_kemdem_encrypt_authenticated_on(curve.curve(), seed, x, y, &payload) {
                Ok(ct) => return Ok(ct),
                Err(ZkKemDemError::RetryNeeded) => continue,
                Err(other) => return Err(js_err(other.to_string())),
            }
        }
        Err(js_err(
            "CSPRNG produced zero scalar repeatedly; system entropy may be broken",
        ))
    }

    /// Curve-generic counterpart of [`decrypt`].
    #[wasm_bindgen(js_name = decryptOn)]
    pub fn decrypt_on(
        curve: &crate::curve::ZkCurve,
        receiver_sec_key_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<js_sys::Array, JsValue> {
        use crate::kemdem_functions::zk_kemdem_decrypt_on;

        let sec_key_le = parse_secret_key_to_le32(receiver_sec_key_hex)?;
        let decrypted = zk_kemdem_decrypt_on(curve.curve(), &sec_key_le, ciphertext_hex)
            .map_err(|e| js_err(e.to_string()))?;
        let arr = js_sys::Array::new_with_length(decrypted.len() as u32);
        for (i, el) in decrypted.iter().enumerate() {
            arr.set(i as u32, JsValue::from_str(&fr_to_be_hex(el)));
        }
        Ok(arr)
    }

    /// Curve-generic counterpart of [`decryptAuthenticated`].
    #[wasm_bindgen(js_name = decryptAuthenticatedOn)]
    pub fn decrypt_authenticated_on(
        curve: &crate::curve::ZkCurve,
        receiver_sec_key_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<js_sys::Array, JsValue> {
        use crate::kemdem_functions::zk_kemdem_decrypt_authenticated_on;

        let sec_key_le = parse_secret_key_to_le32(receiver_sec_key_hex)?;
        let decrypted =
            zk_kemdem_decrypt_authenticated_on(curve.curve(), &sec_key_le, ciphertext_hex)
                .map_err(|e| js_err(e.to_string()))?;
        let arr = js_sys::Array::new_with_length(decrypted.len() as u32);
        for (i, el) in decrypted.iter().enumerate() {
            arr.set(i as u32, JsValue::from_str(&fr_to_be_hex(el)));
        }
        Ok(arr)
    }

    /// Derive a public key from a secret key on the supplied curve.
    /// Returns `{ x, y }` (0x-prefixed BE hex). Useful for verifying
    /// that a JS-derived scalar lands on the expected curve point
    /// without having to re-implement scalar-mul in JS.
    #[wasm_bindgen(js_name = publicKeyFromSecretOn)]
    pub fn public_key_from_secret_on(
        curve: &crate::curve::ZkCurve,
        secret_key_hex: &str,
    ) -> Result<js_sys::Object, JsValue> {
        use crate::kemdem_functions::generate_keypair_from_seed_on;

        // The 32-byte LE secret-key bytes serve directly as the
        // "seed" the dispatcher consumes. For the default curve the
        // dispatcher reduces them mod the BabyJubJub scalar field,
        // which is a no-op on a canonical sk encoding; for custom
        // curves the runtime backend treats them as a 256-bit scalar.
        let seed = parse_secret_key_to_le32(secret_key_hex)?;

        let (_re_sk, x, y) = generate_keypair_from_seed_on(curve.curve(), seed)
            .map_err(|e| js_err(e.to_string()))?;
        let pub_obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &pub_obj,
            &JsValue::from_str("x"),
            &JsValue::from_str(&fr_to_be_hex(&x)),
        )
        .unwrap();
        js_sys::Reflect::set(
            &pub_obj,
            &JsValue::from_str("y"),
            &JsValue::from_str(&fr_to_be_hex(&y)),
        )
        .unwrap();
        Ok(pub_obj)
    }
}

// ── Native tests for the ZK API surface ────────────────────────────

#[cfg(test)]
mod tests {
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
        assert_eq!(
            ct.len(),
            (payload.len() + EPHEM_AND_TAG_ELEMS) * FR_BYTES * 2
        );
    }

    #[test]
    fn zk_encrypt_payload_too_large_is_typed_error() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_encrypt, ZkKemDemError, MAX_PAYLOAD_ELEMS,
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

    #[test]
    fn domain_roundtrip_via_core_api_uncompressed() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_with_domains,
            zk_kemdem_encrypt_with_domains, KemDemDomains,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([20u8; 32]).unwrap();
        let payload = vec![Fr254::from(0xCAFEu64), Fr254::from(0xBEEFu64)];
        let domains = KemDemDomains {
            kem_domain: Fr254::from(0xABCDu64),
            dem_domain: Fr254::from(0x1234u64),
        };
        let ct =
            zk_kemdem_encrypt_with_domains([21u8; 32], &pk, &payload, &domains, false).unwrap();
        let pt = zk_kemdem_decrypt_with_domains(&sk, &ct, &domains, false).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn domain_roundtrip_via_core_api_compressed() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_with_domains,
            zk_kemdem_encrypt_with_domains, KemDemDomains,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([22u8; 32]).unwrap();
        let payload: Vec<Fr254> = (0..7).map(|i| Fr254::from(i as u64 * 11 + 3)).collect();
        let domains = KemDemDomains {
            kem_domain: Fr254::from(0x9999u64),
            dem_domain: Fr254::from(0x8888u64),
        };
        let ct = zk_kemdem_encrypt_with_domains([23u8; 32], &pk, &payload, &domains, true).unwrap();
        let pt = zk_kemdem_decrypt_with_domains(&sk, &ct, &domains, true).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn domain_authenticated_roundtrip_via_core_api() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_authenticated_with_domains,
            zk_kemdem_encrypt_authenticated_with_domains, KemDemDomains,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([24u8; 32]).unwrap();
        let payload = vec![Fr254::from(0xCAFEu64), Fr254::from(0xBEEFu64)];
        let domains = KemDemDomains {
            kem_domain: Fr254::from(0xABCDu64),
            dem_domain: Fr254::from(0x1234u64),
        };
        let ct = zk_kemdem_encrypt_authenticated_with_domains(
            [25u8; 32], &pk, &payload, &domains, false,
        )
        .unwrap();
        let pt = zk_kemdem_decrypt_authenticated_with_domains(&sk, &ct, &domains, false).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn domain_authenticated_compressed_roundtrip_via_core_api() {
        use crate::kemdem_functions::{
            generate_keypair_from_seed, zk_kemdem_decrypt_authenticated_with_domains,
            zk_kemdem_encrypt_authenticated_with_domains, KemDemDomains,
        };
        use ark_bn254::Fr as Fr254;

        let (sk, pk) = generate_keypair_from_seed([26u8; 32]).unwrap();
        let payload: Vec<Fr254> = (0..4).map(|i| Fr254::from(i as u64 * 17 + 5)).collect();
        let domains = KemDemDomains {
            kem_domain: Fr254::from(0x7777u64),
            dem_domain: Fr254::from(0x3333u64),
        };
        let ct =
            zk_kemdem_encrypt_authenticated_with_domains([27u8; 32], &pk, &payload, &domains, true)
                .unwrap();
        let pt = zk_kemdem_decrypt_authenticated_with_domains(&sk, &ct, &domains, true).unwrap();
        assert_eq!(pt, payload);
    }
}
