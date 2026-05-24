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

/// Number of bytes in a 256-bit field element on the wire.
const FIELD_BYTES: usize = 32;

/// Strip an optional `0x`/`0X` prefix, trim whitespace, and left-pad
/// to an even number of hex digits.
fn clean_hex(s: &str) -> String {
    let trimmed = s.trim_start_matches("0x").trim_start_matches("0X").trim();
    if trimmed.len() % 2 != 0 {
        format!("0{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// Decode a big-endian hex string into a left-padded 32-byte array.
/// Returns `Ok(None)` for the empty string so the caller can decide
/// whether to map that to zero or reject it.
fn decode_be_32(s: &str) -> Result<Option<[u8; FIELD_BYTES]>, String> {
    let clean = clean_hex(s);
    if clean.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(&clean).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() > FIELD_BYTES {
        return Err(format!("hex string longer than {FIELD_BYTES} bytes"));
    }
    let mut out = [0u8; FIELD_BYTES];
    out[FIELD_BYTES - bytes.len()..].copy_from_slice(&bytes);
    Ok(Some(out))
}

/// Generic canonical parser: reduces the decoded bytes mod `F`'s
/// modulus, then rejects the input if the round-trip representation
/// differs (i.e. the input was ≥ the modulus and got silently reduced).
///
/// `to_canonical_bytes` lowers the reduced element back to the same
/// byte order (`big_endian` true → BE, false → LE) that `bytes_input`
/// is in, so the two can be compared without ordering bugs.
fn parse_canonical<F, FromBytes, ToBytes>(
    s: &str,
    label: &str,
    empty_allowed: bool,
    big_endian: bool,
    from_bytes: FromBytes,
    to_canonical_bytes: ToBytes,
) -> Result<F, String>
where
    F: ark_ff::Zero,
    FromBytes: Fn(&[u8]) -> F,
    ToBytes: Fn(&F) -> Vec<u8>,
{
    let Some(be_bytes) = decode_be_32(s)? else {
        if empty_allowed {
            return Ok(F::zero());
        }
        return Err(format!("{label} hex is empty"));
    };

    // The arithmetic libs all expose their `from_bytes_mod_order`
    // primitives in one of LE / BE flavours; we keep both branches.
    let canonical_input: Vec<u8> = if big_endian {
        be_bytes.to_vec()
    } else {
        let mut le = be_bytes;
        le.reverse();
        le.to_vec()
    };

    let el = from_bytes(&canonical_input);

    let mut canonical = to_canonical_bytes(&el);
    if canonical.len() < FIELD_BYTES {
        let mut padded = vec![0u8; FIELD_BYTES - canonical.len()];
        padded.extend(canonical);
        canonical = padded;
    }
    canonical.resize(FIELD_BYTES, 0);
    if canonical != canonical_input {
        return Err(format!(
            "{label} is not a canonical field element (>= field modulus)"
        ));
    }
    Ok(el)
}

/// Parse a big-endian hex string into a BN254 `Fr` element, *rejecting*
/// values ≥ the field modulus instead of silently reducing.
pub(crate) fn parse_fr_be(s: &str) -> Result<ark_bn254::Fr, String> {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};

    parse_canonical(
        s,
        "value",
        /* empty_allowed */ true,
        /* big_endian   */ true,
        Fr::from_be_bytes_mod_order,
        |el| el.into_bigint().to_bytes_be(),
    )
}

/// Parse a big-endian hex string directly into a BabyJubJub scalar,
/// rejecting values ≥ the subgroup order instead of silently reducing.
pub(crate) fn parse_babyjubjub_scalar_be(s: &str) -> Result<taceo_ark_babyjubjub::Fr, String> {
    use ark_ff::{BigInteger, PrimeField};
    use taceo_ark_babyjubjub::Fr as BabyJubJubScalar;

    parse_canonical(
        s,
        "secret key",
        /* empty_allowed */ false,
        /* big_endian   */ false,
        BabyJubJubScalar::from_le_bytes_mod_order,
        |el| el.into_bigint().to_bytes_le(),
    )
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
        let p_hex = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
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
        let pm1_hex = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
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
