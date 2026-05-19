use hkdf::Hkdf;
use sha2::Sha256;

/// Derives a field-specific key from the KEM shared secret using HKDF-SHA256.
/// The field name acts as the domain separation context, ensuring unique keys
/// per field even under the same encapsulation.
pub fn derive_field_key(shared_secret: &[u8; 32], field_name: &str) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(field_name.as_bytes(), &mut key)
        .expect("HKDF expansion to 32 bytes is infallible with SHA256");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_field_key_deterministic() {
        let ss = [0x42u8; 32];
        let key1 = derive_field_key(&ss, "field1");
        let key2 = derive_field_key(&ss, "field1");
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_field_key_different_fields_different_keys() {
        let ss = [0x42u8; 32];
        let key1 = derive_field_key(&ss, "field1");
        let key2 = derive_field_key(&ss, "field2");
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_field_key_different_secrets_different_keys() {
        let ss1 = [0x42u8; 32];
        let ss2 = [0x43u8; 32];
        let key1 = derive_field_key(&ss1, "same_field");
        let key2 = derive_field_key(&ss2, "same_field");
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_field_key_not_all_zeros() {
        let ss = [0x42u8; 32];
        let key = derive_field_key(&ss, "test");
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn derive_field_key_empty_field_name() {
        let ss = [0x42u8; 32];
        let key = derive_field_key(&ss, "");
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn derive_field_key_long_field_name() {
        let ss = [0x42u8; 32];
        let long_name = "a".repeat(1000);
        let key = derive_field_key(&ss, &long_name);
        assert_ne!(key, [0u8; 32]);
        assert_eq!(key.len(), 32);
    }
}
