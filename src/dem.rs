use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use crate::error::CryptoError;

/// Generic DEM interface.
pub trait Dem {
    fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub struct Aes256GcmDem;

impl Dem for Aes256GcmDem {
    fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = cipher.encrypt(nonce, plaintext).map_err(CryptoError::from)?;

        // nonce (12 bytes) || ciphertext
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 12 {
            return Err(CryptoError::new(
                "Ciphertext too short (must include 12-byte nonce)".to_string(),
            ));
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, encrypted).map_err(CryptoError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, KEM-DEM!";
        let ciphertext = Aes256GcmDem::encrypt(&key, plaintext).unwrap();
        // Should be nonce (12) + ciphertext + tag (16) = 12 + 15 + 16 = 43
        assert_eq!(ciphertext.len(), 12 + plaintext.len() + 16);
        let decrypted = Aes256GcmDem::decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256gcm_different_keys_fail() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"secret data";
        let ciphertext = Aes256GcmDem::encrypt(&key1, plaintext).unwrap();
        let result = Aes256GcmDem::decrypt(&key2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn aes256gcm_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"tamper test";
        let mut ciphertext = Aes256GcmDem::encrypt(&key, plaintext).unwrap();
        // Tamper with the last byte
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        let result = Aes256GcmDem::decrypt(&key, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn aes256gcm_ciphertext_too_short() {
        let key = [0x42u8; 32];
        let short = vec![0u8; 11];
        let result = Aes256GcmDem::decrypt(&key, &short);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("too short"));
    }

    #[test]
    fn aes256gcm_empty_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = b"";
        let ciphertext = Aes256GcmDem::encrypt(&key, plaintext).unwrap();
        // nonce (12) + tag (16) only
        assert_eq!(ciphertext.len(), 12 + 16);
        let decrypted = Aes256GcmDem::decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256gcm_large_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MiB
        let ciphertext = Aes256GcmDem::encrypt(&key, &plaintext).unwrap();
        let decrypted = Aes256GcmDem::decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256gcm_unique_nonces() {
        let key = [0x42u8; 32];
        let plaintext = b"nonce test";
        let ct1 = Aes256GcmDem::encrypt(&key, plaintext).unwrap();
        let ct2 = Aes256GcmDem::encrypt(&key, plaintext).unwrap();
        // First 12 bytes are nonces; they should differ with overwhelming probability
        assert_ne!(&ct1[..12], &ct2[..12]);
        // Both should decrypt successfully
        assert_eq!(Aes256GcmDem::decrypt(&key, &ct1).unwrap(), plaintext);
        assert_eq!(Aes256GcmDem::decrypt(&key, &ct2).unwrap(), plaintext);
    }
}
