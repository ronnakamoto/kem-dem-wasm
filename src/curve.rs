//! Curve parameter abstraction for the ZK-friendly KEM-DEM.
//!
//! A [`Curve`] carries the full description of a twisted-Edwards
//! curve over the BN254 scalar field `Fr254`:
//!
//! ```text
//! a · x² + y² = 1 + d · x² · y²
//! ```
//!
//! plus a generator `(gx, gy)` that lies in a prime-order subgroup
//! of order `n`, with cofactor `h` (the curve order is `n · h`).
//!
//! The crate ships a built-in [`Curve::default_v1`] whose parameters
//! exactly match the constants this library has used since `0.1.0`,
//! so existing callers see byte-identical wire output.
//!
//! Custom curves can be constructed via [`Curve::new_validated`]
//! (Rust) or `new ZkCurve(...)` (JS); they are validated at
//! construction time:
//!
//! - `(gx, gy)` lies on the supplied curve (algebraic check).
//! - `(gx, gy)` is not the twisted-Edwards identity `(0, 1)`.
//! - `scalar_order · (gx, gy) == identity` (subgroup-membership
//!   check via the runtime arithmetic backend in [`crate::te_arith`]).
//!
//! Custom curves are routed through the runtime arithmetic backend
//! at encrypt/decrypt time; the built-in default curve continues to
//! use the audited typed `taceo-ark-babyjubjub` pipeline so existing
//! ciphertexts stay byte-identical.

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, BigInteger256, Field, LegendreSymbol, One, Zero};
use std::fmt;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::hex_util::{js_err, parse_fr_be_labeled};

/// Errors produced while constructing or validating a [`Curve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurveError {
    /// `(gx, gy)` does not satisfy `a · x² + y² = 1 + d · x² · y²`.
    GeneratorNotOnCurve,
    /// `(gx, gy)` is the twisted-Edwards identity `(0, 1)`.
    GeneratorIsIdentity,
    /// `(gx, gy)` is on the curve but `scalar_order · (gx, gy)` is
    /// not the identity, so the supplied `scalar_order` does not
    /// describe the prime-order subgroup containing the generator.
    GeneratorNotInSubgroup,
    /// `cofactor` is zero — meaningless for a curve.
    ZeroCofactor,
    /// `scalar_order` is zero.
    ZeroScalarOrder,
    /// The curve is not complete (either `a` is not a square or `d` is a square).
    IncompleteCurve,
}

impl fmt::Display for CurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CurveError::GeneratorNotOnCurve => f.write_str(
                "generator (gx, gy) does not satisfy the supplied curve equation",
            ),
            CurveError::GeneratorIsIdentity => {
                f.write_str("generator must not be the twisted-Edwards identity (0, 1)")
            }
            CurveError::GeneratorNotInSubgroup => f.write_str(
                "generator is on the curve but `scalar_order · (gx, gy)` is not the \
                 identity; `scalar_order` does not describe the subgroup containing \
                 the generator",
            ),
            CurveError::ZeroCofactor => f.write_str("cofactor must be non-zero"),
            CurveError::ZeroScalarOrder => f.write_str("scalar_order must be non-zero"),
            CurveError::IncompleteCurve => f.write_str("curve is incomplete: `a` must be a square and `d` a non-square"),
        }
    }
}

impl std::error::Error for CurveError {}

/// Twisted-Edwards curve parameters over BN254 `Fr`.
///
/// Equality is structural: two curves are equal iff every parameter
/// matches bit-for-bit. This is what the dispatcher in
/// [`crate::kemdem_functions`] uses to route between the typed
/// arithmetic backend (for [`Curve::default_v1`]) and the runtime
/// backend (for custom curves).
#[derive(Clone, PartialEq, Eq)]
pub struct Curve {
    /// Curve coefficient `a`.
    pub a: Fr254,
    /// Curve coefficient `d`.
    pub d: Fr254,
    /// Generator x-coordinate.
    pub gx: Fr254,
    /// Generator y-coordinate.
    pub gy: Fr254,
    /// Order of the prime-order subgroup containing `(gx, gy)`.
    pub scalar_order: BigInteger256,
    /// Cofactor `h` such that the full curve order is `scalar_order · cofactor`.
    pub cofactor: u64,
}

impl Curve {
    /// Built-in curve. Constants are exactly the values this crate
    /// has used since `0.1.0`, so [`crate::ZkEncryptor`]'s pre-existing
    /// API and the new `*On(curve, ...)` API produce byte-identical
    /// output when both are called with this curve.
    pub fn default_v1() -> Self {
        // Curve coefficients: a = 168700, d = 168696.
        let a = Fr254::from(168700u64);
        let d = Fr254::from(168696u64);

        // Generator (twisted-Edwards form).
        let gx = Fr254::from_str(
            "16540640123574156134436876038791482806971768689494387082833631921987005038935",
        )
        .expect("default_v1 generator x is a valid BN254 Fr");
        let gy = Fr254::from_str(
            "20819045374670962167435360035096875258406992893633759881276124905556507972311",
        )
        .expect("default_v1 generator y is a valid BN254 Fr");

        // Prime-order subgroup order (BabyJubJub Fr): a 251-bit prime.
        // 2736030358979909402780800718157159386076813972158567259200215660948447373041
        let scalar_order = BigInteger256::new([
            0x677297dc392126f1,
            0xab3eedb83920ee0a,
            0x370a08b6d0302b0b,
            0x060c89ce5c263405,
        ]);

        // Cofactor.
        let cofactor = 8u64;

        Curve {
            a,
            d,
            gx,
            gy,
            scalar_order,
            cofactor,
        }
    }

    /// Construct a [`Curve`] from raw parameters and run all
    /// algebraic validation immediately. See [`CurveError`] for
    /// the failure modes.
    pub fn new_validated(
        a: Fr254,
        d: Fr254,
        gx: Fr254,
        gy: Fr254,
        scalar_order: BigInteger256,
        cofactor: u64,
    ) -> Result<Self, CurveError> {
        if cofactor == 0 {
            return Err(CurveError::ZeroCofactor);
        }
        if scalar_order.is_zero() {
            return Err(CurveError::ZeroScalarOrder);
        }
        // Completeness check: a must be square, d must be non-square
        // to guarantee the denominator in the addition formula never vanishes.
        if a.legendre() != LegendreSymbol::QuadraticResidue {
            return Err(CurveError::IncompleteCurve);
        }
        if d.legendre() != LegendreSymbol::QuadraticNonResidue {
            return Err(CurveError::IncompleteCurve);
        }
        // Identity check: (0, 1) is the TE identity.
        if gx.is_zero() && gy.is_one() {
            return Err(CurveError::GeneratorIsIdentity);
        }
        // On-curve check: a·x² + y² = 1 + d·x²·y²  (in Fr254).
        let x2 = gx * gx;
        let y2 = gy * gy;
        let lhs = a * x2 + y2;
        let rhs = Fr254::one() + d * x2 * y2;
        if lhs != rhs {
            return Err(CurveError::GeneratorNotOnCurve);
        }

        let candidate = Curve {
            a,
            d,
            gx,
            gy,
            scalar_order,
            cofactor,
        };

        // Subgroup-membership check: `scalar_order · G == identity`.
        // Catches a frequent footgun where the caller supplies the
        // *full* curve order (n · h) instead of the prime subgroup
        // order n, or pastes in a totally unrelated number. Applies
        // to the built-in default curve too — it's a cheap belt-and-
        // braces guard that runs once per `Curve` construction.
        let g = crate::te_arith::TePoint {
            x: candidate.gx,
            y: candidate.gy,
        };
        if !crate::te_arith::is_in_subgroup(&candidate, &g) {
            return Err(CurveError::GeneratorNotInSubgroup);
        }

        Ok(candidate)
    }
}

impl fmt::Debug for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Curve")
            .field("a", &self.a.to_string())
            .field("d", &self.d.to_string())
            .field("gx", &self.gx.to_string())
            .field("gy", &self.gy.to_string())
            .field("scalar_order", &self.scalar_order.to_string())
            .field("cofactor", &self.cofactor)
            .finish()
    }
}

/// WASM-facing handle for a [`Curve`].
///
/// JavaScript constructs one of these once per recipient curve and
/// passes it into the `*On` family of methods on [`crate::ZkEncryptor`].
#[wasm_bindgen]
pub struct ZkCurve {
    inner: Curve,
}

impl ZkCurve {
    /// Internal accessor used by the `*On` dispatchers. Not exposed
    /// to JavaScript.
    pub(crate) fn curve(&self) -> &Curve {
        &self.inner
    }
}

#[wasm_bindgen]
impl ZkCurve {
    /// Construct a curve from JS-side parameters.
    ///
    /// All field elements are 0x-prefixed BE hex strings. `scalar_order`
    /// is a base-10 decimal string (BigInt-friendly). `cofactor` is a
    /// small positive integer.
    ///
    /// Throws if any parameter is non-canonical or if the curve fails
    /// validation (see [`CurveError`]).
    #[wasm_bindgen(constructor)]
    pub fn new(
        a_be_hex: &str,
        d_be_hex: &str,
        gx_be_hex: &str,
        gy_be_hex: &str,
        scalar_order_decimal: &str,
        cofactor: u64,
    ) -> Result<ZkCurve, JsValue> {
        let a = parse_fr_be_labeled(a_be_hex, "a").map_err(js_err)?;
        let d = parse_fr_be_labeled(d_be_hex, "d").map_err(js_err)?;
        let gx = parse_fr_be_labeled(gx_be_hex, "gx").map_err(js_err)?;
        let gy = parse_fr_be_labeled(gy_be_hex, "gy").map_err(js_err)?;

        // BigInteger256 doesn't impl FromStr for decimal; route through
        // an Fr254 reduction-free decode by way of a 256-bit BigInt.
        let scalar_order = parse_decimal_to_bigint256(scalar_order_decimal).map_err(js_err)?;

        let inner = Curve::new_validated(a, d, gx, gy, scalar_order, cofactor)
            .map_err(|e| js_err(e.to_string()))?;
        Ok(ZkCurve { inner })
    }

    /// Returns the built-in default curve (matches the constants this
    /// crate has used since `0.1.0`).
    #[wasm_bindgen(js_name = defaultV1)]
    pub fn default_v1() -> ZkCurve {
        ZkCurve {
            inner: Curve::default_v1(),
        }
    }

    /// Convenience: returns true iff this curve equals the built-in
    /// default. Useful for client-side sanity checks.
    #[wasm_bindgen(js_name = isDefaultV1)]
    pub fn is_default_v1(&self) -> bool {
        self.inner == Curve::default_v1()
    }

    /// 0x-prefixed BE hex of the generator x-coordinate.
    #[wasm_bindgen(getter)]
    pub fn gx(&self) -> String {
        crate::hex_util::fr_to_be_hex(&self.inner.gx)
    }

    /// 0x-prefixed BE hex of the generator y-coordinate.
    #[wasm_bindgen(getter)]
    pub fn gy(&self) -> String {
        crate::hex_util::fr_to_be_hex(&self.inner.gy)
    }
}

/// Parse a base-10 decimal string into a 256-bit big-endian integer
/// stored as `BigInteger256` (LE-limbed). Rejects values that do not
/// fit in 256 bits.
fn parse_decimal_to_bigint256(s: &str) -> Result<BigInteger256, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("scalar_order is empty".to_string());
    }
    // Build the integer by repeated multiply-by-10 and add-digit using
    // an `[u64; 4]` accumulator. This avoids an extra dependency.
    let mut limbs = [0u64; 4];
    for ch in trimmed.chars() {
        let digit = ch
            .to_digit(10)
            .ok_or_else(|| format!("scalar_order: invalid digit '{ch}'"))?
            as u64;
        // multiply limbs by 10
        let mut carry: u128 = 0;
        for limb in limbs.iter_mut() {
            let v = (*limb as u128) * 10 + carry;
            *limb = v as u64;
            carry = v >> 64;
        }
        if carry != 0 {
            return Err("scalar_order does not fit in 256 bits".to_string());
        }
        // add digit
        let mut carry: u128 = digit as u128;
        for limb in limbs.iter_mut() {
            let v = (*limb as u128) + carry;
            *limb = v as u64;
            carry = v >> 64;
            if carry == 0 {
                break;
            }
        }
        if carry != 0 {
            return Err("scalar_order does not fit in 256 bits".to_string());
        }
    }
    Ok(BigInteger256::new(limbs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_v1_passes_on_curve_check() {
        let c = Curve::default_v1();
        // Re-run the algebraic check that `new_validated` would do.
        let x2 = c.gx * c.gx;
        let y2 = c.gy * c.gy;
        assert_eq!(c.a * x2 + y2, Fr254::one() + c.d * x2 * y2);
    }

    #[test]
    fn default_v1_scalar_order_is_correct() {
        // 2736030358979909402780800718157159386076813972158567259200215660948447373041
        let expected = parse_decimal_to_bigint256(
            "2736030358979909402780800718157159386076813972158567259200215660948447373041",
        )
        .unwrap();
        assert_eq!(Curve::default_v1().scalar_order, expected);
    }

    #[test]
    fn new_validated_accepts_default() {
        let c = Curve::default_v1();
        let rebuilt = Curve::new_validated(c.a, c.d, c.gx, c.gy, c.scalar_order, c.cofactor)
            .expect("default_v1 must round-trip new_validated");
        assert_eq!(c, rebuilt);
    }

    #[test]
    fn new_validated_rejects_off_curve_generator() {
        let c = Curve::default_v1();
        // Perturb gx; gy stays the same — point is now off-curve.
        let bad_gx = c.gx + Fr254::one();
        let err = Curve::new_validated(c.a, c.d, bad_gx, c.gy, c.scalar_order, c.cofactor)
            .unwrap_err();
        assert_eq!(err, CurveError::GeneratorNotOnCurve);
    }

    #[test]
    fn new_validated_rejects_identity_generator() {
        let c = Curve::default_v1();
        let err = Curve::new_validated(
            c.a,
            c.d,
            Fr254::zero(),
            Fr254::one(),
            c.scalar_order,
            c.cofactor,
        )
        .unwrap_err();
        assert_eq!(err, CurveError::GeneratorIsIdentity);
    }

    #[test]
    fn new_validated_rejects_zero_cofactor() {
        let c = Curve::default_v1();
        let err =
            Curve::new_validated(c.a, c.d, c.gx, c.gy, c.scalar_order, 0).unwrap_err();
        assert_eq!(err, CurveError::ZeroCofactor);
    }

    #[test]
    fn new_validated_rejects_zero_scalar_order() {
        let c = Curve::default_v1();
        let err = Curve::new_validated(
            c.a,
            c.d,
            c.gx,
            c.gy,
            BigInteger256::zero(),
            c.cofactor,
        )
        .unwrap_err();
        assert_eq!(err, CurveError::ZeroScalarOrder);
    }

    #[test]
    fn new_validated_accepts_custom_curve() {
        // Same parameters as `default_v1` except cofactor; the
        // subgroup check still passes (it depends only on a, d, gx,
        // gy, scalar_order), and Phase-2 lifted the dispatcher gate
        // so this must round-trip.
        let c = Curve::default_v1();
        let bogus_cofactor = c.cofactor + 1;
        let custom = Curve::new_validated(c.a, c.d, c.gx, c.gy, c.scalar_order, bogus_cofactor)
            .expect("validated custom curve must be accepted");
        assert_ne!(custom, Curve::default_v1());
        assert_eq!(custom.cofactor, bogus_cofactor);
    }

    #[test]
    fn new_validated_rejects_out_of_subgroup_generator() {
        // Supply a scalar_order that does *not* annihilate the
        // generator. `n - 1` is the simplest such value: it gives
        // `(n-1) · G = -G ≠ identity`. The on-curve and identity
        // checks pass, so the failure must be the new subgroup check.
        let c = Curve::default_v1();
        let mut wrong_n = c.scalar_order;
        let _ = wrong_n.sub_with_borrow(&BigInteger256::from(1u64));

        let err = Curve::new_validated(c.a, c.d, c.gx, c.gy, wrong_n, c.cofactor)
            .unwrap_err();
        assert_eq!(err, CurveError::GeneratorNotInSubgroup);
    }

    #[test]
    fn parse_decimal_round_trip() {
        let s = "2736030358979909402780800718157159386076813972158567259200215660948447373041";
        let bi = parse_decimal_to_bigint256(s).unwrap();
        assert_eq!(bi.to_string().to_lowercase(), s.to_lowercase());
    }

    #[test]
    fn parse_decimal_rejects_overflow() {
        // 2^256 = 1 followed by 256 zero bits. Decimal:
        // 115792089237316195423570985008687907853269984665640564039457584007913129639936
        let too_big =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(parse_decimal_to_bigint256(too_big).is_err());
    }

    #[test]
    fn parse_decimal_rejects_garbage() {
        assert!(parse_decimal_to_bigint256("0xff").is_err());
        assert!(parse_decimal_to_bigint256("").is_err());
        assert!(parse_decimal_to_bigint256("not a number").is_err());
    }
}
