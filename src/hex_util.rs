//! Shared hex/Fr/scalar parsing helpers used by the WASM-facing APIs.
//!
//! All `parse_*` functions reject non-canonical encodings (values that
//! would silently reduce mod the field order). Silent reduction would
//! let a malicious encoder produce two distinct hex inputs that map
//! to the same `Fr` — for receiver public-key coordinates this could
//! let an attacker claim "I sent to X" while actually targeting a
//! reduced X', and for payload elements it introduces an unnecessary
//! malleability axis beyond what the DEM already has.

use wasm_bindgen::JsValue;

/// Build a JS `Error`-style value from any string-like message.
pub(crate) fn js_err<S: Into<String>>(msg: S) -> JsValue {
    JsValue::from_str(&msg.into())
}

/// Single helper for CSPRNG draws across the ZK API. Uses `OsRng`
/// directly (which delegates each draw to `getrandom`) rather than
/// re-seeding a `StdRng` each call.
pub(crate) fn fill_random(buf: &mut [u8]) {
    use rand::{rngs::OsRng, TryRngCore};
    OsRng
        .try_fill_bytes(buf)
        .expect("OS CSPRNG (getrandom) failed; system entropy is broken");
}

/// Parse a big-endian hex string into a BN254 `Fr` element, *rejecting*
/// values ≥ the field modulus instead of silently reducing.
pub(crate) fn parse_fr_be(s: &str) -> Result<ark_bn254::Fr, String> {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField, Zero};

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

    let el = Fr::from_be_bytes_mod_order(&bytes);

    // Roundtrip check: the canonical big-endian representation of the
    // reduced value must equal the input. If they differ, the input was
    // ≥ the field modulus and got silently reduced — reject it.
    let mut canonical_be = el.into_bigint().to_bytes_be();
    if canonical_be.len() < 32 {
        let mut padded = vec![0u8; 32 - canonical_be.len()];
        padded.extend(canonical_be);
        canonical_be = padded;
    }
    if canonical_be != bytes {
        return Err(
            "value is not a canonical BN254 Fr element (>= field modulus)".to_string(),
        );
    }

    Ok(el)
}

/// Parse a big-endian hex string directly into a BabyJubJub scalar,
/// rejecting values ≥ the subgroup order instead of silently reducing.
pub(crate) fn parse_babyjubjub_scalar_be(
    s: &str,
) -> Result<taceo_ark_babyjubjub::Fr, String> {
    use ark_ff::{BigInteger, PrimeField};
    use taceo_ark_babyjubjub::Fr as BabyJubJubScalar;

    let clean = s.trim_start_matches("0x").trim_start_matches("0X").trim();
    if clean.is_empty() {
        return Err("secret key hex is empty".to_string());
    }
    let clean = if clean.len() % 2 != 0 {
        format!("0{clean}")
    } else {
        clean.to_string()
    };
    let bytes = hex::decode(&clean).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() > 32 {
        return Err("secret key hex longer than 32 bytes".to_string());
    }
    // Pad to 32 bytes big-endian, then convert to LE for ark-ff.
    let mut le = vec![0u8; 32];
    le[32 - bytes.len()..].copy_from_slice(&bytes);
    le.reverse();
    let scalar = BabyJubJubScalar::from_le_bytes_mod_order(&le);
    let mut canonical_le = scalar.into_bigint().to_bytes_le();
    canonical_le.resize(32, 0);
    if canonical_le != le {
        return Err(
            "secret key is not a canonical BabyJubJub scalar (value >= subgroup order)"
                .to_string(),
        );
    }
    Ok(scalar)
}

/// Encode a BN254 `Fr` element as a 0x-prefixed 64-char big-endian hex
/// string. Always left-pads to 32 bytes; never truncates.
pub(crate) fn fr_to_be_hex(el: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let be = el.into_bigint().to_bytes_be();
    debug_assert!(be.len() <= 32, "BN254 Fr must encode in ≤ 32 bytes");
    let mut bytes = vec![0u8; 32];
    bytes[32 - be.len()..].copy_from_slice(&be);
    format!("0x{}", hex::encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fr_be_rejects_value_at_modulus() {
        // BN254 Fr modulus:
        // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        let p_hex =
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        assert!(
            parse_fr_be(p_hex).is_err(),
            "p (the modulus itself) must be rejected as non-canonical"
        );
    }

    #[test]
    fn parse_fr_be_rejects_value_above_modulus() {
        let all_ones = format!("0x{}", "ff".repeat(32));
        assert!(parse_fr_be(&all_ones).is_err());
    }

    #[test]
    fn parse_fr_be_accepts_canonical_values() {
        let pm1_hex =
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
        assert!(parse_fr_be(pm1_hex).is_ok(), "p-1 must be accepted");
        assert!(parse_fr_be("0x01").is_ok());
        assert!(parse_fr_be("0x00").is_ok());
        assert!(parse_fr_be("0x").is_ok());
    }

    #[test]
    fn parse_babyjubjub_scalar_be_rejects_non_canonical() {
        let all_ones = format!("0x{}", "ff".repeat(32));
        assert!(parse_babyjubjub_scalar_be(&all_ones).is_err());
    }
}
