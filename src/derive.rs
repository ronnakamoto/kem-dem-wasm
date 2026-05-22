//! Deterministic X25519 key derivation from Ethereum wallet material.
//!
//! This module implements the derivation scheme described in the
//! project README: BIP-32 child private key
//! (or `keccak256(personal_sign(...))`) → HKDF-SHA256 → X25519 keypair.
//!
//! The derived keys are fully compatible with the existing HPKE
//! `setup_sender` / `setup_receiver` in [`crate::kem`].

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use hpke::{kem::Kem as KemTrait, Deserializable, Serializable};

use crate::error::CryptoError;
use crate::kem::HpkeKem;

// ── Constants ──────────────────────────────────────────────────────

/// Input to SHA-256 to produce the fixed HKDF salt.
const HKDF_SALT_INPUT: &[u8] = b"kem-dem-wasm/v1/x25519-derivation-salt";

/// Prefix for the HKDF `info` parameter; the hex-encoded EVM address
/// is appended to produce per-account domain separation.
const HKDF_INFO_PREFIX: &[u8] = b"kem-dem-wasm/v1/x25519/";

/// Domain-separator prefix mixed into `keccak256` when deriving an IKM
/// from a `personal_sign` signature. Prevents the same wallet signature
/// from being repurposed by another library to derive a colliding key.
pub const SIG_IKM_DOMAIN: &[u8] = b"kem-dem-wasm/v1/sig-to-ikm/";

/// secp256k1 group order n, big-endian.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// secp256k1 order n / 2, big-endian. Signatures with `s > HALF_N` are
/// the non-canonical (high-s) half of the malleable pair; we flip them
/// to low-s before hashing so the IKM is independent of which half a
/// signer happens to emit (EIP-2 style).
const SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// BIP-44 derivation path for the encryption sub-tree.
///
/// `m/44'/60'/0'/2147483647'/0`
///
/// * `44'` — BIP-44 purpose
/// * `60'` — Ethereum coin type
/// * `0'`  — first account
/// * `2147483647'` — hardened "poison" change index; deliberately not
///   `0` or `1` to avoid collision with signing/change paths
/// * `0`   — first key index
///
/// The JS wallet-side derives to this path (using ethers/viem) and
/// passes the 32-byte child private key as `ikm` to
/// [`derive_keypair_from_ikm`].
pub const ENCRYPTION_DERIVATION_PATH: &str = "m/44'/60'/0'/2147483647'/0";

// ── Public API ─────────────────────────────────────────────────────

/// Deterministically derive an X25519 keypair from input keying material
/// and a 20-byte EVM address.
///
/// `ikm` is typically a 32-byte BIP-32 child private key (from the path
/// [`ENCRYPTION_DERIVATION_PATH`]) or `keccak256(personal_sign(…))`.
///
/// The EVM address is bound into the HKDF `info` string (hex-encoded,
/// lower-case) so that derivations for different addresses from the
/// same seed produce distinct keypairs.
///
/// Returns `(public_key, secret_key)` — both 32 bytes, directly usable
/// with `encrypt_fields` / `decrypt_fields`.
pub fn derive_keypair_from_ikm(
    ikm: &[u8],
    eth_address: &[u8; 20],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if ikm.len() < 16 {
        return Err(CryptoError::new(
            "IKM must be at least 16 bytes of entropy".into(),
        ));
    }

    // Fixed salt = SHA-256(domain string).
    let salt = Sha256::digest(HKDF_SALT_INPUT);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), ikm);

    // info = prefix || hex(address)  — human-readable, frozen as wire format.
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 40);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(hex::encode(eth_address).as_bytes());

    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm)
        .map_err(|_| CryptoError::new("HKDF expand failed".into()))?;

    // Deserialise the 32 raw bytes as an HPKE secret key.  For X25519
    // the `from_bytes` path accepts any 32 bytes (clamping happens at
    // DH time inside the hpke crate, which mirrors RFC 7748 §5).
    let secret_key = <<HpkeKem as KemTrait>::PrivateKey as Deserializable>::from_bytes(&okm)
        .map_err(|_| {
            CryptoError::new("Failed to construct HPKE secret key from derived bytes".into())
        })?;

    okm.zeroize();

    // Compute the public key using the hpke crate's own scalar-mul.
    let public_key = HpkeKem::sk_to_pk(&secret_key);

    Ok((
        public_key.to_bytes().as_slice().to_vec(),
        secret_key.to_bytes().as_slice().to_vec(),
    ))
}

/// Canonicalises a 65-byte secp256k1 signature `r ‖ s ‖ v` by forcing
/// the `s` component to the low half of the group (EIP-2).
///
/// If `s > n/2`, replaces `s` with `n - s` and flips the recovery bit
/// in `v`. This guarantees that the two valid representations of the
/// same signature collapse to a single canonical form, so the derived
/// IKM is independent of which form a given wallet emits.
pub fn canonicalise_secp256k1_signature(sig: &[u8]) -> Result<[u8; 65], CryptoError> {
    if sig.len() != 65 {
        return Err(CryptoError::new(
            "Signature must be exactly 65 bytes (r||s||v)".into(),
        ));
    }

    let mut out = [0u8; 65];
    out.copy_from_slice(sig);

    if cmp_be(&out[32..64], &SECP256K1_HALF_N) == core::cmp::Ordering::Greater {
        // s := n - s
        let s: &[u8; 32] = out[32..64].try_into().unwrap();
        let new_s = sub_be_32(&SECP256K1_N, s);
        out[32..64].copy_from_slice(&new_s);
        // Flip recovery bit. `personal_sign` outputs use either the
        // legacy {27,28} encoding or the raw {0,1} encoding; we handle
        // both. (EIP-155 encoded `v` is transaction-only, not relevant
        // here.)
        out[64] = match out[64] {
            0 => 1,
            1 => 0,
            27 => 28,
            28 => 27,
            other => {
                return Err(CryptoError::new(format!(
                    "Unexpected recovery byte v={other}; expected 0, 1, 27 or 28"
                )));
            }
        };
    }

    Ok(out)
}

/// Derive a 32-byte IKM from a `personal_sign` signature.
///
/// Canonicalises the signature (low-s) and then computes
/// `keccak256(SIG_IKM_DOMAIN ‖ canonical_sig)`. The domain separator
/// prevents collision with any other library that hashes the raw
/// signature for its own purposes.
///
/// # ⚠️ Determinism requirement
///
/// This whole derivation pipeline is **only secure for the user** if
/// the signer always produces the *same* signature for the *same*
/// message. Modern software wallets (MetaMask, Rabby, Frame, ethers,
/// viem) all sign deterministically per RFC 6979, so this holds in
/// practice. **However:**
///
/// - Some hardware wallets (older Trezor firmware, custom HSMs) may
///   randomise the `k` nonce. Signing the same message twice yields
///   two different signatures and therefore two different encryption
///   keys, locking the user out of past ciphertexts.
/// - The low-s canonicalisation collapses the malleability axis, but
///   does **not** repair non-deterministic `k`.
///
/// Callers SHOULD use [`verify_signature_derivation_is_deterministic`]
/// (or an equivalent JS-side double-derive check) before persisting
/// any ciphertext under the resulting keypair.
pub fn derive_ikm_from_signature(sig: &[u8]) -> Result<[u8; 32], CryptoError> {
    use sha3::{Digest, Keccak256};
    let mut canonical = canonicalise_secp256k1_signature(sig)?;

    let mut hasher = Keccak256::new();
    hasher.update(SIG_IKM_DOMAIN);
    hasher.update(canonical);
    let result = hasher.finalize().into();

    canonical.zeroize();
    Ok(result)
}

/// Checks whether two signatures over the *same* canonical derivation
/// message produce the *same* IKM. Returns `Ok(())` if they do; an
/// error otherwise.
///
/// JS callers should prompt the wallet twice for the derivation
/// signature on first use, then call this. A mismatch indicates the
/// signer is non-deterministic (randomised `k`) and must NOT be used
/// to derive an encryption key — the user would lose access to past
/// ciphertexts the next time they re-sign.
///
/// Note: this only checks the IKM stage, which is the part affected
/// by signer determinism. The subsequent HKDF and X25519 derivation
/// are pure functions of the IKM, so IKM-equal ⇒ keypair-equal.
pub fn verify_signature_derivation_is_deterministic(
    sig_a: &[u8],
    sig_b: &[u8],
) -> Result<(), CryptoError> {
    let ikm_a = derive_ikm_from_signature(sig_a)?;
    let ikm_b = derive_ikm_from_signature(sig_b)?;
    // Constant-time compare to avoid leaking which byte mismatched —
    // the IKM is secret-equivalent.
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= ikm_a[i] ^ ikm_b[i];
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(CryptoError::new(
            "signer is non-deterministic (two signatures over the same message produced \
             different IKMs); derived encryption key would change on every sign"
                .into(),
        ))
    }
}

/// Big-endian compare of two equal-length byte slices.
fn cmp_be(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    debug_assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    core::cmp::Ordering::Equal
}

/// Big-endian 32-byte subtraction `a - b`. Caller guarantees `a >= b`.
fn sub_be_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::X25519Hpke;

    /// Fixed test vector — if this breaks, the derivation wire format changed.
    const TEST_IKM: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    const TEST_ADDR: [u8; 20] = [
        0xd8, 0xda, 0x6b, 0xf2, 0x69, 0x64, 0xaf, 0x9d, 0x7e, 0xed, 0x9e, 0x03, 0xe5, 0x34, 0x15,
        0xd3, 0x7a, 0xa9, 0x60, 0x45,
    ];

    #[test]
    fn deterministic_derivation() {
        let (pk1, sk1) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();
        let (pk2, sk2) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();
        assert_eq!(pk1, pk2, "same inputs must produce same public key");
        assert_eq!(sk1, sk2, "same inputs must produce same secret key");
    }

    #[test]
    fn different_address_different_key() {
        let addr2: [u8; 20] = [0xAA; 20];
        let (pk1, _) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();
        let (pk2, _) = derive_keypair_from_ikm(&TEST_IKM, &addr2).unwrap();
        assert_ne!(pk1, pk2, "different address must produce different key");
    }

    #[test]
    fn different_ikm_different_key() {
        let ikm2 = [0xFF; 32];
        let (pk1, _) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();
        let (pk2, _) = derive_keypair_from_ikm(&ikm2, &TEST_ADDR).unwrap();
        assert_ne!(pk1, pk2, "different IKM must produce different key");
    }

    #[test]
    fn rejects_short_ikm() {
        let short = [0u8; 15];
        let result = derive_keypair_from_ikm(&short, &TEST_ADDR);
        assert!(result.is_err());
    }

    #[test]
    fn accepts_16_byte_ikm() {
        let ikm = [0x42u8; 16];
        let result = derive_keypair_from_ikm(&ikm, &TEST_ADDR);
        assert!(result.is_ok());
    }

    #[test]
    fn derived_key_sizes() {
        let (pk, sk) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();
        assert_eq!(pk.len(), 32, "X25519 public key must be 32 bytes");
        assert_eq!(sk.len(), 32, "X25519 secret key must be 32 bytes");
    }

    #[test]
    fn derived_keys_roundtrip_with_hpke() {
        // Derive a keypair
        let (pk, sk) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();

        // Encrypt with the derived public key using the existing HPKE API
        let info = b"kem-dem-wasm/v1/derive-test";
        let (encapped_key, mut sender) = X25519Hpke::setup_sender(&pk, info).unwrap();
        let ciphertext = sender.seal(b"test-aad", b"secret payload").unwrap();

        // Decrypt with the derived secret key
        let mut receiver = X25519Hpke::setup_receiver(&sk, &encapped_key, info).unwrap();
        let plaintext = receiver.open(b"test-aad", &ciphertext).unwrap();

        assert_eq!(plaintext, b"secret payload");
    }

    #[test]
    fn public_key_not_all_zeros() {
        let (pk, _) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();
        assert_ne!(pk, vec![0u8; 32], "public key must not be all zeros");
    }

    #[test]
    fn encryption_derivation_path_is_correct() {
        assert_eq!(ENCRYPTION_DERIVATION_PATH, "m/44'/60'/0'/2147483647'/0");
    }

    /// Pin the HKDF salt value. If this breaks, the wire format
    /// changed — coordinate with `docs/test-vectors.md`.
    #[test]
    fn hkdf_salt_value_is_pinned() {
        let salt = Sha256::digest(HKDF_SALT_INPUT);
        assert_eq!(
            hex::encode(salt),
            "161962a5d0a626f3f621428f82d6fdc3a83822a92be2abcd42d0901b54f94e96",
            "HKDF salt value changed — wire format is incompatible"
        );
    }

    // ─── secp256k1 low-s canonicalisation ───────────────────────

    #[test]
    fn canonicalise_rejects_wrong_length() {
        assert!(canonicalise_secp256k1_signature(&[0u8; 64]).is_err());
        assert!(canonicalise_secp256k1_signature(&[0u8; 66]).is_err());
    }

    #[test]
    fn canonicalise_keeps_low_s_unchanged() {
        // s = 1 is trivially low.
        let mut sig = [0u8; 65];
        sig[63] = 0x01; // s = 1, big-endian
        sig[64] = 27;
        let canon = canonicalise_secp256k1_signature(&sig).unwrap();
        assert_eq!(canon, sig, "low-s signature must be returned unchanged");
    }

    #[test]
    fn canonicalise_flips_high_s() {
        // s = n - 1 is high; canonical s = 1, v flipped.
        let mut sig = [0u8; 65];
        // n - 1, big-endian
        let n_minus_1 = sub_be_32(&SECP256K1_N, &{
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        });
        sig[32..64].copy_from_slice(&n_minus_1);
        sig[64] = 27;

        let canon = canonicalise_secp256k1_signature(&sig).unwrap();
        // s should now be 1
        let mut expected_s = [0u8; 32];
        expected_s[31] = 1;
        assert_eq!(
            &canon[32..64],
            &expected_s,
            "high-s must be flipped to low-s"
        );
        assert_eq!(canon[64], 28, "recovery bit must flip 27 -> 28");
    }

    #[test]
    fn canonicalise_is_idempotent() {
        // Apply twice → same result. Use a valid high-s value (n - 7).
        let mut sig = [0u8; 65];
        let mut seven = [0u8; 32];
        seven[31] = 7;
        let high_s = sub_be_32(&SECP256K1_N, &seven);
        sig[32..64].copy_from_slice(&high_s);
        sig[64] = 28;
        let once = canonicalise_secp256k1_signature(&sig).unwrap();
        let twice = canonicalise_secp256k1_signature(&once).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn canonicalise_high_s_v01_flips_to_10() {
        // v ∈ {0, 1} form (some wallets use this) must also flip correctly.
        let mut sig = [0u8; 65];
        let mut three = [0u8; 32];
        three[31] = 3;
        let high_s = sub_be_32(&SECP256K1_N, &three);
        sig[32..64].copy_from_slice(&high_s);
        sig[64] = 0;
        let canon = canonicalise_secp256k1_signature(&sig).unwrap();
        assert_eq!(canon[64], 1);
    }

    #[test]
    fn sig_to_ikm_is_deterministic() {
        let mut sig = [0u8; 65];
        sig[63] = 0x42;
        sig[64] = 27;
        let a = derive_ikm_from_signature(&sig).unwrap();
        let b = derive_ikm_from_signature(&sig).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sig_to_ikm_collapses_malleable_pair() {
        // Build a low-s signature and its high-s counterpart; the IKM
        // must be identical because the function canonicalises both.
        let mut low = [0u8; 65];
        low[63] = 0x01;
        low[64] = 27;

        let mut high = [0u8; 65];
        let n_minus_1 = sub_be_32(&SECP256K1_N, &{
            let mut one = [0u8; 32];
            one[31] = 1;
            one
        });
        high[32..64].copy_from_slice(&n_minus_1);
        high[64] = 28;

        let ikm_low = derive_ikm_from_signature(&low).unwrap();
        let ikm_high = derive_ikm_from_signature(&high).unwrap();
        assert_eq!(
            ikm_low, ikm_high,
            "malleable signature pair must yield the same IKM"
        );
    }

    #[test]
    fn sig_to_ikm_has_domain_separation() {
        // Raw keccak of the signature must differ from our domain-prefixed keccak.
        use sha3::{Digest, Keccak256};
        let mut sig = [0u8; 65];
        sig[63] = 0x01;
        sig[64] = 27;

        let raw: [u8; 32] = Keccak256::digest(sig).into();
        let domained = derive_ikm_from_signature(&sig).unwrap();
        assert_ne!(raw, domained, "domain separator must change the output");
    }

    /// Pinned test vector — if this breaks, the derivation wire format
    /// changed and all existing derived keys are incompatible.
    /// See `docs/test-vectors.md` for the canonical values.
    #[test]
    fn pinned_test_vector() {
        let (pk, sk) = derive_keypair_from_ikm(&TEST_IKM, &TEST_ADDR).unwrap();
        assert_eq!(
            hex::encode(&sk),
            "e10720f42730f9b07b4e724a226f101372bb24fd4e56ab8ad31c040d3eb2003b",
            "secret key does not match pinned test vector"
        );
        assert_eq!(
            hex::encode(&pk),
            "21ab02c2b9e78a8bba19dabbf1a88a69d8042163a477cec1ad74e78903a7ee78",
            "public key does not match pinned test vector"
        );
    }
}
