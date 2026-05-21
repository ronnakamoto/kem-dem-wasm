use hpke::{
    aead::{AeadCtxR, AeadCtxS, AesGcm256},
    kdf::HkdfSha256,
    kem::{Kem as KemTrait, X25519HkdfSha256},
    setup_receiver, setup_sender, Deserializable, OpModeR, OpModeS, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};

use crate::error::CryptoError;

pub type HpkeKem = X25519HkdfSha256;
pub type HpkeAead = AesGcm256;
pub type HpkeKdf = HkdfSha256;

type HpkePublicKey = <HpkeKem as KemTrait>::PublicKey;
type HpkeSecretKey = <HpkeKem as KemTrait>::PrivateKey;
type HpkeEncappedKey = <HpkeKem as KemTrait>::EncappedKey;

pub struct SenderContext(AeadCtxS<HpkeAead, HpkeKdf, HpkeKem>);

impl SenderContext {
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.seal(plaintext, aad).map_err(CryptoError::from)
    }
}

pub struct ReceiverContext(AeadCtxR<HpkeAead, HpkeKdf, HpkeKem>);

impl ReceiverContext {
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0.open(ciphertext, aad).map_err(CryptoError::from)
    }
}

pub struct X25519Hpke;

impl X25519Hpke {
    #[cfg(test)]
    pub fn public_key_size() -> usize {
        HpkePublicKey::size()
    }

    #[cfg(test)]
    pub fn secret_key_size() -> usize {
        HpkeSecretKey::size()
    }

    #[cfg(test)]
    pub fn encapped_key_size() -> usize {
        HpkeEncappedKey::size()
    }

    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = StdRng::from_os_rng();
        let (secret_key, public_key) = HpkeKem::gen_keypair(&mut rng);
        (
            public_key.to_bytes().as_slice().to_vec(),
            secret_key.to_bytes().as_slice().to_vec(),
        )
    }

    pub fn setup_sender(
        recipient_public_key: &[u8],
        info: &[u8],
    ) -> Result<(Vec<u8>, SenderContext), CryptoError> {
        let recipient_public_key = HpkePublicKey::from_bytes(recipient_public_key)?;
        let mut rng = StdRng::from_os_rng();
        let (encapped_key, context) = setup_sender::<HpkeAead, HpkeKdf, HpkeKem, _>(
            &OpModeS::Base,
            &recipient_public_key,
            info,
            &mut rng,
        )
        .map_err(CryptoError::from)?;

        Ok((
            encapped_key.to_bytes().as_slice().to_vec(),
            SenderContext(context),
        ))
    }

    pub fn setup_receiver(
        recipient_secret_key: &[u8],
        encapped_key: &[u8],
        info: &[u8],
    ) -> Result<ReceiverContext, CryptoError> {
        let recipient_secret_key = HpkeSecretKey::from_bytes(recipient_secret_key)?;
        let encapped_key = HpkeEncappedKey::from_bytes(encapped_key)?;
        let context = setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &recipient_secret_key,
            &encapped_key,
            info,
        )
        .map_err(CryptoError::from)?;

        Ok(ReceiverContext(context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_keypair_generation() {
        let (pk, sk) = X25519Hpke::generate_keypair();
        assert_eq!(pk.len(), X25519Hpke::public_key_size());
        assert_eq!(sk.len(), X25519Hpke::secret_key_size());
        assert_ne!(sk, vec![0u8; X25519Hpke::secret_key_size()]);
    }

    #[test]
    fn hpke_setup_sender_receiver_roundtrip() {
        let (pk, sk) = X25519Hpke::generate_keypair();
        let (encapped_key, mut sender) =
            X25519Hpke::setup_sender(&pk, b"kem-dem-wasm/test").unwrap();
        let ciphertext = sender.seal(b"field:a", b"secret payload").unwrap();

        let mut receiver =
            X25519Hpke::setup_receiver(&sk, &encapped_key, b"kem-dem-wasm/test").unwrap();
        let plaintext = receiver.open(b"field:a", &ciphertext).unwrap();

        assert_eq!(plaintext, b"secret payload");
    }

    #[test]
    fn hpke_multiple_setups_different_encapped_keys() {
        let (pk, _sk) = X25519Hpke::generate_keypair();
        let (enc1, _sender1) = X25519Hpke::setup_sender(&pk, b"kem-dem-wasm/test").unwrap();
        let (enc2, _sender2) = X25519Hpke::setup_sender(&pk, b"kem-dem-wasm/test").unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn hpke_wrong_secret_key_fails() {
        let (pk1, _sk1) = X25519Hpke::generate_keypair();
        let (_pk2, sk2) = X25519Hpke::generate_keypair();

        let (encapped_key, mut sender) =
            X25519Hpke::setup_sender(&pk1, b"kem-dem-wasm/test").unwrap();
        let ciphertext = sender.seal(b"field:a", b"secret payload").unwrap();

        let mut receiver =
            X25519Hpke::setup_receiver(&sk2, &encapped_key, b"kem-dem-wasm/test").unwrap();
        let result = receiver.open(b"field:a", &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn hpke_invalid_public_key_length_fails() {
        let result = X25519Hpke::setup_sender(&[0u8; 31], b"kem-dem-wasm/test");
        assert!(result.is_err());
    }

    #[test]
    fn hpke_invalid_secret_key_length_fails() {
        let result = X25519Hpke::setup_receiver(&[0u8; 31], &[0u8; 32], b"kem-dem-wasm/test");
        assert!(result.is_err());
    }

    #[test]
    fn hpke_aad_mismatch_fails() {
        let (pk, sk) = X25519Hpke::generate_keypair();
        let (encapped_key, mut sender) =
            X25519Hpke::setup_sender(&pk, b"kem-dem-wasm/test").unwrap();
        let ciphertext = sender.seal(b"field:a", b"secret payload").unwrap();

        let mut receiver =
            X25519Hpke::setup_receiver(&sk, &encapped_key, b"kem-dem-wasm/test").unwrap();
        let result = receiver.open(b"field:b", &ciphertext);
        assert!(result.is_err());
    }
}
