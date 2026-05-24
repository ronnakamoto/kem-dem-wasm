//! WASM-facing HPKE (RFC 9180) API: `KemDem`, `KeyPair`,
//! `EncryptedPackage`, `EncryptedBlob`.
//!
//! See `lib.rs` for the wire-format constants and the rationale behind
//! the v2 manifest-binding scheme.

use std::collections::BTreeMap;

use js_sys::Uint8Array;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::derive::{
    derive_ikm_from_signature, derive_keypair_from_ikm,
    verify_signature_derivation_is_deterministic, ENCRYPTION_DERIVATION_PATH,
};
use crate::error::{to_js_value, CryptoError};
use crate::kem::X25519Hpke;

// ── Wire-format constants ─────────────────────────────────────────

/// v2 of the field-package wire format binds a *manifest hash* of the
/// sorted field-name list as AAD on every sealed field. This closes the
/// silent field-drop / field-add attack that v1 was vulnerable to: any
/// tampering with the set of fields changes the manifest the receiver
/// recomputes, and every AEAD verification then fails.
///
/// v1 ciphertexts are NOT decryptable by v2 (intentional, since the
/// security property differs). Bump the major version of the crate when
/// you ship this change.
pub(crate) const FIELD_PACKAGE_INFO: &[u8] = b"kem-dem-wasm/v2/field-package";
pub(crate) const FIELD_PACKAGE_AAD_PREFIX: &[u8] = b"kem-dem-wasm/v2/field:";
pub(crate) const FIELD_PACKAGE_MANIFEST_PREFIX: &[u8] = b"kem-dem-wasm/v2/manifest:";
pub(crate) const BLOB_INFO: &[u8] = b"kem-dem-wasm/v1/blob";
pub(crate) const BLOB_AAD: &[u8] = b"kem-dem-wasm/v1/blob-payload";

/// Maximum number of fields per `encryptFields` call. HPKE seal
/// implicitly advances an AEAD nonce per call (capped at 2⁹⁶ for
/// AES-GCM), so the protocol-level ceiling is astronomically higher;
/// this constant is a *policy* cap to bound memory, JS round-trip cost,
/// and the impact of a malicious `{a, b, …}` JSON object trying to
/// consume gigabytes of WASM heap before we notice.
pub const MAX_FIELD_COUNT: usize = 1 << 16; // 65 536

/// Maximum byte length per field value. Same rationale as above: the
/// AEAD primitive permits far more, but a single-MB string in a single
/// field is almost certainly a bug or an attack.
pub const MAX_FIELD_VALUE_LEN: usize = 16 * 1024 * 1024; // 16 MiB

// ── KemDem main API ───────────────────────────────────────────────

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

        // Defensive bounds: fail fast and clearly instead of running
        // out of WASM heap mid-loop on a malicious or buggy caller.
        if input_map.len() > MAX_FIELD_COUNT {
            return Err(to_js_value(CryptoError::new(format!(
                "field count {} exceeds maximum of {MAX_FIELD_COUNT}",
                input_map.len()
            ))));
        }
        for (name, value) in &input_map {
            if value.len() > MAX_FIELD_VALUE_LEN {
                return Err(to_js_value(CryptoError::new(format!(
                    "field '{name}' value of {} bytes exceeds maximum of {MAX_FIELD_VALUE_LEN}",
                    value.len()
                ))));
            }
        }

        let (encapped_key, mut sender) =
            X25519Hpke::setup_sender(public_key, FIELD_PACKAGE_INFO).map_err(to_js_value)?;

        // Bind the full sorted-field-name set as AAD on every field so
        // dropping/adding/renaming any field invalidates the entire
        // package on decrypt.
        let manifest = manifest_hash(input_map.keys().map(String::as_str));

        let mut encrypted_fields = BTreeMap::new();
        for (field_name, field_value) in input_map {
            let encrypted = sender
                .seal(&field_aad(&field_name, &manifest), field_value.as_bytes())
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

        // Recompute the manifest from the keys actually present in the
        // package. If the sender's set differs in any way (added,
        // dropped, renamed field) the AAD mismatch will cause every
        // AEAD `open` below to fail.
        let manifest = manifest_hash(package.encrypted_fields.keys().map(String::as_str));

        let decrypted_fields = js_sys::Object::new();
        for (field_name, field_ct) in &package.encrypted_fields {
            let decrypted = receiver
                .open(&field_aad(field_name, &manifest), field_ct)
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
    #[wasm_bindgen(js_name = encryptionDerivationPath)]
    pub fn encryption_derivation_path() -> String {
        ENCRYPTION_DERIVATION_PATH.to_string()
    }

    /// Deterministically derive an X25519 keypair from input keying
    /// material (typically a BIP-32 child private key) and a 20-byte
    /// EVM address.
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

    /// Verify that two signatures over the *same* derivation message
    /// produce the same derived IKM (i.e. that the wallet signs
    /// deterministically per RFC 6979).
    #[wasm_bindgen(js_name = verifySignerIsDeterministic)]
    pub fn verify_signer_is_deterministic(sig_a: &[u8], sig_b: &[u8]) -> Result<(), JsValue> {
        verify_signature_derivation_is_deterministic(sig_a, sig_b).map_err(to_js_value)
    }

    /// Derive an X25519 keypair from a `personal_sign` signature over
    /// the canonical derivation message and a 20-byte EVM address.
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
    pub(crate) public_key: Vec<u8>,
    pub(crate) secret_key: Zeroizing<Vec<u8>>,
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
    pub(crate) encapped_key: Vec<u8>,
    pub(crate) encrypted_fields: BTreeMap<String, Vec<u8>>,
}

#[wasm_bindgen]
impl EncryptedPackage {
    /// Reconstruct from JS (e.g., after loading from storage).
    ///
    /// Validates the encapsulated-key length up front so a malformed
    /// package surfaces a clear error here instead of a confusing
    /// HPKE-internal failure at decrypt time.
    #[wasm_bindgen(constructor)]
    pub fn new(kem_ciphertext: &[u8], encrypted_fields: JsValue) -> Result<Self, JsValue> {
        use hpke::{kem::Kem as KemTrait, Serializable};
        let expected_len = <<crate::kem::HpkeKem as KemTrait>::EncappedKey as Serializable>::size();
        if kem_ciphertext.len() != expected_len {
            return Err(to_js_value(CryptoError::new(format!(
                "kem_ciphertext length {} does not match HPKE encapped-key size of {expected_len} bytes",
                kem_ciphertext.len()
            ))));
        }

        let fields: BTreeMap<String, Vec<u8>> =
            from_value(encrypted_fields).map_err(|e| to_js_value(CryptoError::from(e)))?;
        if fields.len() > MAX_FIELD_COUNT {
            return Err(to_js_value(CryptoError::new(format!(
                "field count {} exceeds maximum of {MAX_FIELD_COUNT}",
                fields.len()
            ))));
        }
        // Per-ciphertext cap: ciphertext = plaintext + AES-GCM tag.
        // We allow `MAX_FIELD_VALUE_LEN + AEAD_TAG_LEN` so any value
        // that round-trips through `encrypt_fields` is acceptable here,
        // and reject anything larger to bound WASM heap allocation
        // when loading a stored / attacker-supplied package.
        const AEAD_TAG_LEN: usize = 16; // AES-GCM-256 tag
        let max_ct_len = MAX_FIELD_VALUE_LEN + AEAD_TAG_LEN;
        for (name, ct) in &fields {
            if ct.len() > max_ct_len {
                return Err(to_js_value(CryptoError::new(format!(
                    "field '{name}' ciphertext of {} bytes exceeds maximum of {max_ct_len}",
                    ct.len()
                ))));
            }
        }
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
        )?;

        let fields = js_sys::Object::new();
        for (name, value) in &self.encrypted_fields {
            js_sys::Reflect::set(
                &fields,
                &JsValue::from_str(name),
                &Uint8Array::from(&value[..]),
            )?;
        }
        js_sys::Reflect::set(&obj, &JsValue::from_str("encryptedFields"), &fields)?;

        Ok(obj.into())
    }
}

/// Result of single-blob encryption.
#[wasm_bindgen]
#[derive(Clone)]
pub struct EncryptedBlob {
    pub(crate) encapped_key: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
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

// ── Manifest / AAD helpers ────────────────────────────────────────

/// AAD layout: `FIELD_PACKAGE_AAD_PREFIX || field_name || 0x00 || manifest_hash`
///
/// The trailing 0x00 byte is an unambiguous separator between the
/// (variable-length) field name and the (fixed 32-byte) manifest hash,
/// preventing a `("ab", manifest_for_X)` AAD from being confused with
/// `("a", b ‖ manifest_for_X)`.
pub(crate) fn field_aad(field_name: &str, manifest: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FIELD_PACKAGE_AAD_PREFIX.len() + field_name.len() + 1 + 32);
    aad.extend_from_slice(FIELD_PACKAGE_AAD_PREFIX);
    aad.extend_from_slice(field_name.as_bytes());
    aad.push(0x00);
    aad.extend_from_slice(manifest);
    aad
}

/// Deterministic, length-prefixed hash over the canonical sorted list
/// of field names. Length-prefixing every name prevents the trivial
/// collision `["ab", "c"]` vs `["a", "bc"]`.
///
/// Caller MUST pass names in sorted order (the BTreeMap iteration on
/// both sender and receiver does this naturally).
pub(crate) fn manifest_hash<'a, I: Iterator<Item = &'a str>>(field_names: I) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(FIELD_PACKAGE_MANIFEST_PREFIX);
    for name in field_names {
        let len_be = (name.len() as u32).to_be_bytes();
        hasher.update(len_be);
        hasher.update(name.as_bytes());
    }
    hasher.finalize().into()
}

// ── Native-only inner helpers (no `JsValue`, usable from `cargo test --lib`) ──

/// `(encapped_key, field_name -> ciphertext)` produced by the
/// test-only native field encryptor.
#[cfg(test)]
type SealedFields = (Vec<u8>, BTreeMap<String, Vec<u8>>);

#[cfg(test)]
pub(crate) fn encrypt_fields_native(
    public_key: &[u8],
    input_map: &BTreeMap<String, Vec<u8>>,
) -> Result<SealedFields, CryptoError> {
    let (encapped_key, mut sender) = X25519Hpke::setup_sender(public_key, FIELD_PACKAGE_INFO)?;
    let manifest = manifest_hash(input_map.keys().map(String::as_str));
    let mut out = BTreeMap::new();
    for (name, value) in input_map {
        let ct = sender.seal(&field_aad(name, &manifest), value)?;
        out.insert(name.clone(), ct);
    }
    Ok((encapped_key, out))
}

#[cfg(test)]
pub(crate) fn decrypt_fields_native(
    secret_key: &[u8],
    encapped_key: &[u8],
    encrypted_fields: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, CryptoError> {
    let mut receiver = X25519Hpke::setup_receiver(secret_key, encapped_key, FIELD_PACKAGE_INFO)?;
    let manifest = manifest_hash(encrypted_fields.keys().map(String::as_str));
    let mut out = BTreeMap::new();
    for (name, ct) in encrypted_fields {
        let pt = receiver.open(&field_aad(name, &manifest), ct)?;
        out.insert(name.clone(), pt);
    }
    Ok(out)
}

// ── Browser / wasm-bindgen tests ──────────────────────────────────

#[cfg(test)]
mod browser_tests {
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

        assert_eq!(package.encapped_key.len(), X25519Hpke::encapped_key_size());
        assert_eq!(package.encrypted_fields.len(), 3);
        assert!(package.encrypted_fields.contains_key("ssn"));
        assert!(package.encrypted_fields.contains_key("dob"));
        assert!(package.encrypted_fields.contains_key("salary"));

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

// ── Native tests (run under `cargo test --lib`, no browser needed) ──

#[cfg(test)]
mod native_tests {
    use super::*;

    fn fresh_hpke_keypair() -> (Vec<u8>, Vec<u8>) {
        X25519Hpke::generate_keypair()
    }

    #[test]
    fn field_drop_is_detected() {
        let (pk, sk) = fresh_hpke_keypair();
        let mut fields = BTreeMap::new();
        fields.insert("a".to_string(), b"alpha".to_vec());
        fields.insert("b".to_string(), b"beta".to_vec());
        fields.insert("c".to_string(), b"gamma".to_vec());

        let (encapped, mut sealed) = encrypt_fields_native(&pk, &fields).unwrap();

        sealed.remove("c");

        let result = decrypt_fields_native(&sk, &encapped, &sealed);
        assert!(
            result.is_err(),
            "dropping a trailing field must invalidate the package"
        );
    }

    #[test]
    fn field_addition_is_detected() {
        let (pk, sk) = fresh_hpke_keypair();
        let mut fields = BTreeMap::new();
        fields.insert("a".to_string(), b"alpha".to_vec());

        let (encapped, mut sealed) = encrypt_fields_native(&pk, &fields).unwrap();
        sealed.insert("z_evil".to_string(), vec![0u8; 32]);

        let result = decrypt_fields_native(&sk, &encapped, &sealed);
        assert!(
            result.is_err(),
            "adding a new field name must invalidate the package"
        );
    }

    #[test]
    fn field_rename_is_detected() {
        let (pk, sk) = fresh_hpke_keypair();
        let mut fields = BTreeMap::new();
        fields.insert("salary".to_string(), b"150000".to_vec());

        let (encapped, sealed) = encrypt_fields_native(&pk, &fields).unwrap();

        let mut tampered = BTreeMap::new();
        let ct = sealed.get("salary").unwrap().clone();
        tampered.insert("bonus".to_string(), ct);

        let result = decrypt_fields_native(&sk, &encapped, &tampered);
        assert!(
            result.is_err(),
            "renaming a field must invalidate the package"
        );
    }

    #[test]
    fn unmodified_package_roundtrips() {
        let (pk, sk) = fresh_hpke_keypair();
        let mut fields = BTreeMap::new();
        fields.insert("ssn".to_string(), b"123-45-6789".to_vec());
        fields.insert("dob".to_string(), b"1990-01-01".to_vec());
        fields.insert("salary".to_string(), b"150000".to_vec());

        let (encapped, sealed) = encrypt_fields_native(&pk, &fields).unwrap();
        let recovered = decrypt_fields_native(&sk, &encapped, &sealed).unwrap();
        assert_eq!(recovered, fields);
    }

    #[test]
    fn manifest_hash_is_length_prefix_collision_free() {
        let a = manifest_hash(["ab", "c"].into_iter());
        let b = manifest_hash(["a", "bc"].into_iter());
        assert_ne!(a, b);
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let a = manifest_hash(["x", "y", "z"].into_iter());
        let b = manifest_hash(["x", "y", "z"].into_iter());
        assert_eq!(a, b);
    }

    /// Pin the manifest-prefix wire constants so an accidental edit
    /// surfaces here, not in a confused interop bug.
    #[test]
    fn manifest_prefix_is_pinned() {
        assert_eq!(FIELD_PACKAGE_MANIFEST_PREFIX, b"kem-dem-wasm/v2/manifest:");
        assert_eq!(FIELD_PACKAGE_AAD_PREFIX, b"kem-dem-wasm/v2/field:");
        assert_eq!(FIELD_PACKAGE_INFO, b"kem-dem-wasm/v2/field-package");
    }

    // The caps must be large enough for normal use but not so large
    // that a malicious caller can OOM the WASM heap before the
    // explicit checks fire. Enforced at compile time so anyone who
    // bumps a constant into a pathological range gets a build error.
    const _: () = assert!(MAX_FIELD_COUNT >= 1024);
    const _: () = assert!(MAX_FIELD_VALUE_LEN >= 1024);
    const _: () = assert!((MAX_FIELD_COUNT as u64) * (MAX_FIELD_VALUE_LEN as u64) <= (1u64 << 40));

    #[test]
    fn hpke_encapped_key_size_is_32() {
        assert_eq!(X25519Hpke::encapped_key_size(), 32);
    }

    #[test]
    fn blob_roundtrip_native() {
        let (pk, sk) = fresh_hpke_keypair();
        let plaintext = b"Hello, native KEM-DEM!".to_vec();

        let (encapped, mut sender) = X25519Hpke::setup_sender(&pk, BLOB_INFO).unwrap();
        let ct = sender.seal(BLOB_AAD, &plaintext).unwrap();

        let mut receiver = X25519Hpke::setup_receiver(&sk, &encapped, BLOB_INFO).unwrap();
        let pt = receiver.open(BLOB_AAD, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn blob_wrong_key_fails_native() {
        let (pk1, _sk1) = fresh_hpke_keypair();
        let (_pk2, sk2) = fresh_hpke_keypair();

        let (encapped, mut sender) = X25519Hpke::setup_sender(&pk1, BLOB_INFO).unwrap();
        let ct = sender.seal(BLOB_AAD, b"secret").unwrap();

        let mut receiver = X25519Hpke::setup_receiver(&sk2, &encapped, BLOB_INFO).unwrap();
        assert!(receiver.open(BLOB_AAD, &ct).is_err());
    }

    #[test]
    fn deterministic_signer_passes_check() {
        use crate::derive::verify_signature_derivation_is_deterministic;
        let mut sig = [0u8; 65];
        sig[63] = 0x42;
        sig[64] = 27;
        verify_signature_derivation_is_deterministic(&sig, &sig).unwrap();
    }

    #[test]
    fn nondeterministic_signer_fails_check() {
        use crate::derive::verify_signature_derivation_is_deterministic;
        let mut sig_a = [0u8; 65];
        sig_a[63] = 0x42;
        sig_a[64] = 27;
        let mut sig_b = [0u8; 65];
        sig_b[63] = 0x43;
        sig_b[64] = 27;
        let err = verify_signature_derivation_is_deterministic(&sig_a, &sig_b).unwrap_err();
        assert!(
            err.to_string().contains("non-deterministic"),
            "error must clearly flag non-determinism, got: {err}"
        );
    }

    #[test]
    fn malleable_pair_still_passes_check() {
        use crate::derive::{verify_signature_derivation_is_deterministic, SIG_IKM_DOMAIN};
        const SECP256K1_N: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];

        let mut low = [0u8; 65];
        low[63] = 0x01;
        low[64] = 27;

        let mut high = [0u8; 65];
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut borrow: i16 = 0;
        let mut s = [0u8; 32];
        for i in (0..32).rev() {
            let diff = SECP256K1_N[i] as i16 - one[i] as i16 - borrow;
            if diff < 0 {
                s[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                s[i] = diff as u8;
                borrow = 0;
            }
        }
        high[32..64].copy_from_slice(&s);
        high[64] = 28;

        let _ = SIG_IKM_DOMAIN;
        verify_signature_derivation_is_deterministic(&low, &high).unwrap();
    }
}
