mod error;
mod kem;

use std::collections::BTreeMap;

use js_sys::Uint8Array;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;

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
            secret_key: sk,
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

        let (encapped_key, mut sender) = X25519Hpke::setup_sender(public_key, FIELD_PACKAGE_INFO)
            .map_err(to_js_value)?;

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
                to_js_value(CryptoError::new(format!("Field '{field_name}' contains invalid UTF-8")))
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
    pub fn decrypt(
        &self,
        secret_key: &[u8],
        blob: &EncryptedBlob,
    ) -> Result<Vec<u8>, JsValue> {
        let mut receiver =
            X25519Hpke::setup_receiver(secret_key, &blob.encapped_key, BLOB_INFO)
                .map_err(to_js_value)?;
        receiver.open(BLOB_AAD, &blob.ciphertext).map_err(to_js_value)
    }
}

// --- WASM Exported Types ---

#[wasm_bindgen]
#[derive(Clone)]
pub struct KeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
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
        self.encrypted_fields.get(name).map(|v| Uint8Array::from(&v[..]))
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
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("encryptedFields"),
            &fields,
        )
        .unwrap();

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

    #[wasm_bindgen_test]
    fn encrypted_blob_new_and_getters() {
        let kem_ct = vec![1u8; X25519Hpke::encapped_key_size()];
        let dem_ct = vec![2u8; 64];
        let blob = EncryptedBlob::new(&kem_ct, &dem_ct);

        assert_eq!(blob.encapped_key.to_vec(), kem_ct);
        assert_eq!(blob.ciphertext.to_vec(), dem_ct);
    }

    #[wasm_bindgen_test]
    fn keypair_lengths() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();
        assert_eq!(kp.public_key().length() as usize, X25519Hpke::public_key_size());
        assert_eq!(kp.secret_key().length() as usize, X25519Hpke::secret_key_size());
    }

    #[wasm_bindgen_test]
    fn kemdem_field_tampering_fails() {
        let kem_dem = KemDem::new();
        let kp = kem_dem.generate_keypair();

        let mut fields = BTreeMap::new();
        fields.insert("ssn".to_string(), "123-45-6789".to_string());
        fields.insert("salary".to_string(), "150000".to_string());

        let js_fields = serde_wasm_bindgen::to_value(&fields).unwrap();
        let mut package = kem_dem.encrypt_fields(&kp.public_key, js_fields).unwrap();
        let field = package.encrypted_fields.get_mut("ssn").unwrap();
        let last = field.len() - 1;
        field[last] ^= 0x01;

        let result = kem_dem.decrypt_fields(&kp.secret_key, &package);
        assert!(result.is_err());
    }
}
