mod derive;
mod error;
mod kem;

use std::collections::BTreeMap;

use js_sys::Uint8Array;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::derive::{
    derive_ikm_from_signature, derive_keypair_from_ikm, ENCRYPTION_DERIVATION_PATH,
};
use crate::error::{to_js_value, CryptoError};
use crate::kem::X25519Hpke;

const FIELD_PACKAGE_INFO: &[u8] = b"kem-dem-wasm/v1/field-package";
const FIELD_PACKAGE_AAD_PREFIX: &[u8] = b"kem-dem-wasm/v1/field:";
const BLOB_INFO: &[u8] = b"kem-dem-wasm/v1/blob";
const BLOB_AAD: &[u8] = b"kem-dem-wasm/v1/blob-payload";

// Initialize panic hook for better debugging in browser console.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Main React-facing API.
#[wasm_bindgen]
pub struct KemDem;

#[wasm_bindgen]
impl KemDem {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    /// Generates an X25519 keypair.
    /// Returns a KeyPair with `publicKey` and `secretKey` as Uint8Arrays.
    #[wasm_bindgen(js_name = generateKeypair)]
    pub fn generate_keypair(&self) -> KeyPair {
        let (pk, sk) = X25519Hpke::generate_keypair();
        KeyPair {
            public_key: pk,
            secret_key: Zeroizing::new(sk),
        }
    }

    /// Encrypts an arbitrary JS object (Record<string, string>) field-by-field.
    /// Each field is sealed under the same HPKE context in deterministic field-name order.
    /// Returns an EncryptedPackage WASM object.
    #[wasm_bindgen(js_name = encryptFields)]
    pub fn encrypt_fields(
        &self,
        public_key: &[u8],
        fields: JsValue,
    ) -> Result<EncryptedPackage, JsValue> {
        let input_map: BTreeMap<String, String> =
            from_value(fields).map_err(|e: serde_wasm_bindgen::Error| CryptoError::from(e))?;

        let (encapped_key, mut sender) =
            X25519Hpke::setup_sender(public_key, FIELD_PACKAGE_INFO).map_err(to_js_value)?;

        let mut encrypted_fields = BTreeMap::new();
        for (field_name, field_value) in input_map {
            let encrypted = sender
                .seal(&field_aad(&field_name), field_value.as_bytes())
                .map_err(to_js_value)?;
            encrypted_fields.insert(field_name, encrypted);
        }

        Ok(EncryptedPackage {
            encapped_key,
            encrypted_fields,
        })
    }

    /// Decrypts an EncryptedPackage back to the original JS object.
    #[wasm_bindgen(js_name = decryptFields)]
    pub fn decrypt_fields(
        &self,
        secret_key: &[u8],
        package: &EncryptedPackage,
    ) -> Result<JsValue, JsValue> {
        let mut receiver =
            X25519Hpke::setup_receiver(secret_key, &package.encapped_key, FIELD_PACKAGE_INFO)
                .map_err(to_js_value)?;

        let decrypted_fields = js_sys::Object::new();
        for (field_name, field_ct) in &package.encrypted_fields {
            let decrypted = receiver
                .open(&field_aad(field_name), field_ct)
                .map_err(to_js_value)?;
            let decrypted_str = String::from_utf8(decrypted).map_err(|_| {
                to_js_value(CryptoError::new(format!(
                    "Field '{field_name}' contains invalid UTF-8"
                )))
            })?;

            js_sys::Reflect::set(
                &decrypted_fields,
                &JsValue::from_str(field_name),
                &JsValue::from_str(&decrypted_str),
            )
            .map_err(|_| {
                to_js_value(CryptoError::new(format!(
                    "Failed to set decrypted field '{field_name}'"
                )))
            })?;
        }

        Ok(decrypted_fields.into())
    }

    /// Low-level single-blob encryption (KEM + DEM without field splitting).
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, public_key: &[u8], plaintext: &[u8]) -> Result<EncryptedBlob, JsValue> {
        let (encapped_key, mut sender) =
            X25519Hpke::setup_sender(public_key, BLOB_INFO).map_err(to_js_value)?;
        let ciphertext = sender.seal(BLOB_AAD, plaintext).map_err(to_js_value)?;

        Ok(EncryptedBlob {
            encapped_key,
            ciphertext,
        })
    }

    /// Low-level single-blob decryption.
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(&self, secret_key: &[u8], blob: &EncryptedBlob) -> Result<Vec<u8>, JsValue> {
        let mut receiver = X25519Hpke::setup_receiver(secret_key, &blob.encapped_key, BLOB_INFO)
            .map_err(to_js_value)?;
        receiver
            .open(BLOB_AAD, &blob.ciphertext)
            .map_err(to_js_value)
    }

    // ── Deterministic X25519 derivation from Ethereum wallet material ──

    /// Returns the canonical BIP-44 derivation path used to derive an
    /// X25519 encryption keypair from an Ethereum HD wallet.
    ///
    /// `m/44'/60'/0'/2147483647'/0`
    ///
    /// Wallet code derives a child private key at this path and passes
    /// the 32-byte child key as `ikm` to [`deriveKeypairFromIkm`].
    #[wasm_bindgen(js_name = encryptionDerivationPath)]
    pub fn encryption_derivation_path() -> String {
        ENCRYPTION_DERIVATION_PATH.to_string()
    }

    /// Deterministically derive an X25519 keypair from input keying
    /// material (typically a BIP-32 child private key) and a 20-byte
    /// EVM address.
    ///
    /// The address is bound into HKDF's `info` so that derivations for
    /// different addresses from the same seed produce distinct keys.
    ///
    /// Returns a `KeyPair` directly usable with `encryptFields`.
    #[wasm_bindgen(js_name = deriveKeypairFromIkm)]
    pub fn derive_keypair_from_ikm(
        &self,
        ikm: &[u8],
        eth_address: &[u8],
    ) -> Result<KeyPair, JsValue> {
        let addr: &[u8; 20] = eth_address.try_into().map_err(|_| {
            to_js_value(CryptoError::new(
                "eth_address must be exactly 20 bytes".into(),
            ))
        })?;
        let (pk, sk) = derive_keypair_from_ikm(ikm, addr).map_err(to_js_value)?;
        Ok(KeyPair {
            public_key: pk,
            secret_key: Zeroizing::new(sk),
        })
    }

    /// Derive an X25519 keypair from a `personal_sign` signature over
    /// the canonical derivation message and a 20-byte EVM address.
    ///
    /// The signature is canonicalised to low-s (EIP-2), then hashed
    /// with a domain separator to produce an IKM, which is fed through
    /// the same HKDF/HPKE pipeline as [`deriveKeypairFromIkm`].
    ///
    /// Use this for MetaMask / EIP-1193 wallets that do not expose
    /// the seed phrase.
    #[wasm_bindgen(js_name = deriveKeypairFromSignature)]
    pub fn derive_keypair_from_signature(
        &self,
        signature: &[u8],
        eth_address: &[u8],
    ) -> Result<KeyPair, JsValue> {
        let addr: &[u8; 20] = eth_address.try_into().map_err(|_| {
            to_js_value(CryptoError::new(
                "eth_address must be exactly 20 bytes".into(),
            ))
        })?;
        let ikm = derive_ikm_from_signature(signature).map_err(to_js_value)?;
        let (pk, sk) = derive_keypair_from_ikm(&ikm, addr).map_err(to_js_value)?;
        Ok(KeyPair {
            public_key: pk,
            secret_key: Zeroizing::new(sk),
        })
    }
}

impl Default for KemDem {
    fn default() -> Self {
        Self::new()
    }
}

// --- WASM Exported Types ---

#[wasm_bindgen]
pub struct KeyPair {
    public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.public_key[..])
    }

    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> Uint8Array {
        Uint8Array::from(&self.secret_key[..])
    }
}

/// Result of field-level encryption.
#[wasm_bindgen]
#[derive(Clone)]
pub struct EncryptedPackage {
    encapped_key: Vec<u8>,
    encrypted_fields: BTreeMap<String, Vec<u8>>,
}

#[wasm_bindgen]
impl EncryptedPackage {
    /// Reconstruct from JS (e.g., after loading from storage).
    /// `encrypted_fields` should be a JS object mapping field names to Uint8Array or number arrays.
    #[wasm_bindgen(constructor)]
    pub fn new(kem_ciphertext: &[u8], encrypted_fields: JsValue) -> Result<Self, JsValue> {
        let fields: BTreeMap<String, Vec<u8>> =
            from_value(encrypted_fields).map_err(|e| to_js_value(CryptoError::from(e)))?;
        Ok(Self {
            encapped_key: kem_ciphertext.to_vec(),
            encrypted_fields: fields,
        })
    }

    #[wasm_bindgen(getter, js_name = kemCiphertext)]
    pub fn kem_ciphertext(&self) -> Uint8Array {
        Uint8Array::from(&self.encapped_key[..])
    }

    #[wasm_bindgen(js_name = getField)]
    pub fn get_field(&self, name: &str) -> Option<Uint8Array> {
        self.encrypted_fields
            .get(name)
            .map(|v| Uint8Array::from(&v[..]))
    }

    #[wasm_bindgen(js_name = fieldNames)]
    pub fn field_names(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        for name in self.encrypted_fields.keys() {
            arr.push(&JsValue::from_str(name));
        }
        arr
    }

    /// Converts to a plain JS object for easier JSON serialization (if you base64-encode the Uint8Arrays on the JS side).
    #[wasm_bindgen(js_name = toObject)]
    pub fn to_object(&self) -> Result<JsValue, JsValue> {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("kemCiphertext"),
            &self.kem_ciphertext(),
        )
        .unwrap();

        let fields = js_sys::Object::new();
        for (name, value) in &self.encrypted_fields {
            js_sys::Reflect::set(
                &fields,
                &JsValue::from_str(name),
                &Uint8Array::from(&value[..]),
            )
            .unwrap();
        }
        js_sys::Reflect::set(&obj, &JsValue::from_str("encryptedFields"), &fields).unwrap();

        Ok(obj.into())
    }
}

/// Result of single-blob encryption.
#[wasm_bindgen]
#[derive(Clone)]
pub struct EncryptedBlob {
    encapped_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedBlob {
    #[wasm_bindgen(constructor)]
    pub fn new(kem_ciphertext: &[u8], dem_ciphertext: &[u8]) -> Self {
        Self {
            encapped_key: kem_ciphertext.to_vec(),
            ciphertext: dem_ciphertext.to_vec(),
        }
    }

    #[wasm_bindgen(getter, js_name = kemCiphertext)]
    pub fn kem_ciphertext(&self) -> Uint8Array {
        Uint8Array::from(&self.encapped_key[..])
    }

    #[wasm_bindgen(getter, js_name = demCiphertext)]
    pub fn dem_ciphertext(&self) -> Uint8Array {
        Uint8Array::from(&self.ciphertext[..])
    }
}

fn field_aad(field_name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FIELD_PACKAGE_AAD_PREFIX.len() + field_name.len());
    aad.extend_from_slice(FIELD_PACKAGE_AAD_PREFIX);
    aad.extend_from_slice(field_name.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn kemdem_generate_keypair() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();
        assert_eq!(kp.public_key.len(), X25519Hpke::public_key_size());
        assert_eq!(kp.secret_key.len(), X25519Hpke::secret_key_size());
    }

    #[wasm_bindgen_test]
    fn kemdem_single_blob_roundtrip() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();
        let plaintext = b"Hello, WASM KEM-DEM!";

        let blob = kem_dem.encrypt(&kp.public_key, plaintext).unwrap();
        let decrypted = kem_dem.decrypt(&kp.secret_key, &blob).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn kemdem_single_blob_wrong_key_fails() {
        let kem_dem = KemDem::new();
        let kp1 = kem_dem.generate_keypair();
        let kp2 = kem_dem.generate_keypair();
        let plaintext = b"secret";

        let blob = kem_dem.encrypt(&kp1.public_key, plaintext).unwrap();
        let result = kem_dem.decrypt(&kp2.secret_key, &blob);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn kemdem_field_encryption_roundtrip() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();

        let mut fields = BTreeMap::new();
        fields.insert("ssn".to_string(), "123-45-6789".to_string());
        fields.insert("dob".to_string(), "1990-01-01".to_string());
        fields.insert("salary".to_string(), "150000".to_string());

        let js_fields = serde_wasm_bindgen::to_value(&fields).unwrap();
        let package = kem_dem.encrypt_fields(&kp.public_key, js_fields).unwrap();

        // Verify package structure
        assert_eq!(package.encapped_key.len(), X25519Hpke::encapped_key_size());
        assert_eq!(package.encrypted_fields.len(), 3);
        assert!(package.encrypted_fields.contains_key("ssn"));
        assert!(package.encrypted_fields.contains_key("dob"));
        assert!(package.encrypted_fields.contains_key("salary"));

        // Decrypt and verify
        let decrypted = kem_dem.decrypt_fields(&kp.secret_key, &package).unwrap();
        let decrypted_map: BTreeMap<String, String> = from_value(decrypted).unwrap();

        assert_eq!(decrypted_map.get("ssn").unwrap(), "123-45-6789");
        assert_eq!(decrypted_map.get("dob").unwrap(), "1990-01-01");
        assert_eq!(decrypted_map.get("salary").unwrap(), "150000");
    }

    #[wasm_bindgen_test]
    fn kemdem_field_encryption_wrong_key_fails() {
        let kem_dem = KemDem::new();
        let kp1 = kem_dem.generate_keypair();
        let kp2 = kem_dem.generate_keypair();

        let mut fields = BTreeMap::new();
        fields.insert("secret".to_string(), "value".to_string());

        let js_fields = serde_wasm_bindgen::to_value(&fields).unwrap();
        let package = kem_dem.encrypt_fields(&kp1.public_key, js_fields).unwrap();

        let result = kem_dem.decrypt_fields(&kp2.secret_key, &package);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn kemdem_empty_fields_roundtrip() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();

        let fields: BTreeMap<String, String> = BTreeMap::new();
        let js_fields = serde_wasm_bindgen::to_value(&fields).unwrap();
        let package = kem_dem.encrypt_fields(&kp.public_key, js_fields).unwrap();

        assert!(package.encrypted_fields.is_empty());

        let decrypted = kem_dem.decrypt_fields(&kp.secret_key, &package).unwrap();
        let decrypted_map: BTreeMap<String, String> = from_value(decrypted).unwrap();
        assert!(decrypted_map.is_empty());
    }

    #[wasm_bindgen_test]
    fn kemdem_large_blob_roundtrip() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MiB

        let blob = kem_dem.encrypt(&kp.public_key, &plaintext).unwrap();
        let decrypted = kem_dem.decrypt(&kp.secret_key, &blob).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[wasm_bindgen_test]
    fn encrypted_package_get_field() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();

        let mut fields = BTreeMap::new();
        fields.insert("a".to_string(), "1".to_string());
        fields.insert("b".to_string(), "2".to_string());

        let js_fields = serde_wasm_bindgen::to_value(&fields).unwrap();
        let package = kem_dem.encrypt_fields(&kp.public_key, js_fields).unwrap();

        assert!(package.get_field("a").is_some());
        assert!(package.get_field("b").is_some());
        assert!(package.get_field("c").is_none());
    }

    #[wasm_bindgen_test]
    fn encrypted_package_field_names() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();

        let mut fields = BTreeMap::new();
        fields.insert("x".to_string(), "1".to_string());
        fields.insert("y".to_string(), "2".to_string());

        let js_fields = serde_wasm_bindgen::to_value(&fields).unwrap();
        let package = kem_dem.encrypt_fields(&kp.public_key, js_fields).unwrap();

        let names = package.field_names();
        assert_eq!(names.length(), 2);
    }
}

// --- ZK Encryption (BabyJubJub + KEM-DEM) ---

pub mod kemdem_functions;

/// ZK-friendly encryptor using a BabyJubJub KEM-DEM over the BN254
/// scalar field `Fr`.
///
/// The keystream PRF is the iden3 `circomlib`-compatible Poseidon
/// hash (`PoseidonEx(t=4)`), so the produced ciphertexts can be
/// verified inside a Circom circuit using `circomlib`'s `Poseidon(3)`
/// and `EscalarMulAny` templates with byte-for-byte agreement.
///
/// **Confidentiality only.** This primitive does not authenticate the
/// ciphertext — an attacker can flip bits to flip plaintext bits.
/// Wrap with a Poseidon-based MAC if you need integrity, or use the
/// HPKE `KemDem` API for non-ZK data.
#[wasm_bindgen]
pub struct ZkEncryptor;

#[wasm_bindgen]
impl ZkEncryptor {
    /// Encrypt a payload of `Fr` elements to a BabyJubJub public key.
    ///
    /// `receiver_pub_x_hex` / `receiver_pub_y_hex` are 0x-prefixed
    /// 64-char hex strings (big-endian) for the receiver's affine
    /// coordinates. `payload_hex_array` is an array of 0x-prefixed
    /// 64-char hex `Fr` elements.
    ///
    /// Returns a hex-encoded ciphertext whose binary form is
    /// `[ct_0..ct_{n-1}, ephem_x, ephem_y]` with each element 32 bytes
    /// little-endian.
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(
        receiver_pub_x_hex: &str,
        receiver_pub_y_hex: &str,
        payload_hex_array: Vec<String>,
    ) -> Result<String, JsValue> {
        use crate::kemdem_functions::{point_from_xy, zk_kemdem_encrypt};

        let x = parse_fr_be(receiver_pub_x_hex).map_err(js_err)?;
        let y = parse_fr_be(receiver_pub_y_hex).map_err(js_err)?;
        let receiver_pub = point_from_xy(x, y)
            .ok_or_else(|| js_err("receiver public key is not on BabyJubJub or not in subgroup"))?;

        let mut payload = Vec::with_capacity(payload_hex_array.len());
        for s in payload_hex_array {
            payload.push(parse_fr_be(&s).map_err(js_err)?);
        }

        let mut seed = [0u8; 32];
        getrandom_02::getrandom(&mut seed).map_err(|_| js_err("CSPRNG unavailable"))?;

        Ok(zk_kemdem_encrypt(seed, &receiver_pub, &payload))
    }

    /// Decrypt a ciphertext produced by [`encrypt`].
    ///
    /// `receiver_sec_key_hex` is the BabyJubJub scalar as a 0x-prefixed
    /// 64-char big-endian hex string. Returns an array of `Fr` element
    /// hex strings (big-endian).
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(
        receiver_sec_key_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<js_sys::Array, JsValue> {
        use crate::kemdem_functions::zk_kemdem_decrypt;
        use ark_ff::{PrimeField, Zero};
        use taceo_ark_babyjubjub::Fr as BabyJubJubScalar;

        let sk_fr = parse_fr_be(receiver_sec_key_hex).map_err(js_err)?;
        let sk_bytes = {
            use ark_ff::BigInteger;
            sk_fr.into_bigint().to_bytes_be()
        };
        let sec_key = BabyJubJubScalar::from_be_bytes_mod_order(&sk_bytes);
        if sec_key.is_zero() {
            return Err(js_err("invalid secret key"));
        }

        let decrypted = zk_kemdem_decrypt(&sec_key, ciphertext_hex).map_err(js_err)?;

        let arr = js_sys::Array::new();
        for el in decrypted {
            arr.push(&JsValue::from_str(&fr_to_be_hex(&el)));
        }
        Ok(arr)
    }

    /// Generate a random BabyJubJub keypair.
    ///
    /// Returns `{ secretKey, publicKey: { x, y } }`, all as
    /// 0x-prefixed 64-char big-endian hex strings. The public key is
    /// uncompressed `(x, y)` so it can be fed directly into a Circom
    /// circuit using `circomlib`'s `EscalarMulAny`.
    #[wasm_bindgen(js_name = generateKeypair)]
    pub fn generate_keypair() -> Result<js_sys::Object, JsValue> {
        use crate::kemdem_functions::generate_keypair_from_seed;
        use ark_ff::PrimeField;

        let mut seed = [0u8; 32];
        getrandom_02::getrandom(&mut seed).map_err(|_| js_err("CSPRNG unavailable"))?;

        let (sk, pk) = generate_keypair_from_seed(seed);

        let sk_bytes = {
            use ark_ff::BigInteger;
            let mut b = sk.into_bigint().to_bytes_be();
            b.resize(32, 0);
            b
        };

        // Sanity: the generated pk must be on-curve & in subgroup.
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

// ── Hex helpers shared by `ZkEncryptor` ───────────────────────────

fn js_err<S: Into<String>>(msg: S) -> JsValue {
    JsValue::from_str(&msg.into())
}

fn parse_fr_be(s: &str) -> Result<ark_bn254::Fr, String> {
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, Zero};

    let clean = s.trim_start_matches("0x").trim_start_matches("0X").trim();
    if clean.is_empty() {
        return Ok(Fr::zero());
    }
    let clean = if clean.len() % 2 != 0 {
        format!("0{clean}")
    } else {
        clean.to_string()
    };
    let mut bytes = hex::decode(&clean).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() > 32 {
        return Err("hex string longer than 32 bytes".to_string());
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend(bytes);
        bytes = padded;
    }
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

fn fr_to_be_hex(el: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let mut bytes = el.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend(bytes);
        bytes = padded;
    } else if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    format!("0x{}", hex::encode(&bytes))
}
