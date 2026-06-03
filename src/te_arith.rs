//! Runtime twisted-Edwards arithmetic over BN254 `Fr`, parameterized
//! by a [`crate::curve::Curve`] handle.
//!
//! This backend exists to support curves other than the built-in
//! default. The default curve continues to route through the
//! compile-time-monomorphized `taceo-ark-babyjubjub` arithmetic in
//! [`crate::kemdem_functions`] so existing ciphertexts stay
//! byte-identical and benefit from arkworks' audited group law.

// The runtime backend is wired into the public dispatcher in a
// subsequent commit; until then its items are reachable only from
// the module's own tests.
#![allow(dead_code)]

//!
//! ## Curve equation
//!
//! ```text
//! a · x² + y² = 1 + d · x² · y²
//! ```
//!
//! ## Group law (affine TE)
//!
//! Identity: `(0, 1)`.
//!
//! Sum of `(x1, y1)` and `(x2, y2)`:
//!
//! ```text
//! x3 = (x1·y2 + y1·x2) / (1 + d·x1·x2·y1·y2)
//! y3 = (y1·y2 − a·x1·x2) / (1 − d·x1·x2·y1·y2)
//! ```
//!
//! TE addition is **complete** when `a` is a square and `d` is a
//! non-square in the base field — true for every curve that passes
//! [`crate::curve::Curve::new_validated`]'s checks (validation is
//! algebraic; the formulas below assume completeness). The
//! denominators above never vanish for points in the prime-order
//! subgroup, which the validator enforces for the generator.
//!
//! ## Scalar multiplication
//!
//! Constant-iteration Montgomery ladder over the canonical bit
//! representation of the scalar. Each iteration performs exactly one
//! point add and one point double, regardless of the bit value, and
//! conditionally swaps internal registers. This is **best-effort**
//! constant-time: the underlying field arithmetic uses arkworks
//! `Fr254` ops which are themselves best-effort constant-time. We
//! make no stronger claim than that.

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

use crate::curve::Curve;

/// Affine twisted-Edwards point over `Fr254`. The identity is
/// represented as `(0, 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TePoint {
    pub x: Fr254,
    pub y: Fr254,
}

impl TePoint {
    /// The TE identity element.
    #[inline]
    pub fn identity() -> Self {
        TePoint {
            x: Fr254::zero(),
            y: Fr254::one(),
        }
    }

    /// Returns `true` if `self` is the TE identity.
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.is_one()
    }

    /// Returns `true` if `self` satisfies `curve`'s equation.
    pub fn is_on_curve(&self, curve: &Curve) -> bool {
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        let lhs = curve.a * x2 + y2;
        let rhs = Fr254::one() + curve.d * x2 * y2;
        lhs == rhs
    }
}

/// Twisted-Edwards point addition (unified formula). Works for any
/// pair of points on the same curve, including doubling and the
/// identity. Panics if a denominator is non-invertible — under
/// `new_validated`'s constraints this only occurs for malformed
/// inputs, which the public API rejects upstream.
pub fn add(curve: &Curve, p: &TePoint, q: &TePoint) -> TePoint {
    let x1y2 = p.x * q.y;
    let y1x2 = p.y * q.x;
    let y1y2 = p.y * q.y;
    let x1x2 = p.x * q.x;
    let dxxyy = curve.d * x1x2 * y1y2;

    let denom_x = Fr254::one() + dxxyy;
    let denom_y = Fr254::one() - dxxyy;

    let inv_x = denom_x
        .inverse()
        .expect("TE addition denominator (1 + d·x1·x2·y1·y2) is non-zero on a complete curve");
    let inv_y = denom_y
        .inverse()
        .expect("TE addition denominator (1 - d·x1·x2·y1·y2) is non-zero on a complete curve");

    let x3 = (x1y2 + y1x2) * inv_x;
    let y3 = (y1y2 - curve.a * x1x2) * inv_y;
    TePoint { x: x3, y: y3 }
}

/// Convenience wrapper around [`add`] for `p + p`.
#[inline]
pub fn double(curve: &Curve, p: &TePoint) -> TePoint {
    add(curve, p, p)
}

/// Scalar multiplication `k · P`.
///
/// `k` is taken in canonical 256-bit little-endian limb form (e.g.
/// the result of `Fr::from_bytes_mod_order(...).into_bigint()`).
/// Returns the TE identity for `k = 0`.
///
/// Implementation: constant-iteration Montgomery ladder driven by
/// the bits of `k` from MSB to LSB. Both registers are points on
/// the curve at every step, so the inner `add`/`double` calls never
/// hit a non-invertible denominator.
pub fn scalar_mul(curve: &Curve, p: &TePoint, k_le_limbs: &[u64]) -> TePoint {
    let mut r0 = TePoint::identity();
    let mut r1 = *p;
    let mut swap = false;

    // Always iterate 256 times to avoid leaking scalar length.
    for i in (0..256).rev() {
        let bit = scalar_bit(k_le_limbs, i);
        let do_swap = bit ^ swap;
        cswap(do_swap, &mut r0, &mut r1);
        swap = bit;

        r1 = add(curve, &r0, &r1);
        r0 = double(curve, &r0);
    }
    cswap(swap, &mut r0, &mut r1);

    r0
}

#[inline(always)]
fn cswap(swap: bool, a: &mut TePoint, b: &mut TePoint) {
    let mask_fr = Fr254::from(swap as u64);
    let t_x = (b.x - a.x) * mask_fr;
    a.x += t_x;
    b.x -= t_x;

    let t_y = (b.y - a.y) * mask_fr;
    a.y += t_y;
    b.y -= t_y;
}

/// Returns true iff `p` lies in the prime-order subgroup of order
/// `curve.scalar_order`. Computes `n · P` and tests for the identity.
pub fn is_in_subgroup(curve: &Curve, p: &TePoint) -> bool {
    let n_limbs = curve.scalar_order.0;
    scalar_mul(curve, p, &n_limbs).is_identity()
}

/// Compressed-serialization sign predicate matching arkworks'
/// `CanonicalSerialize` for `twisted_edwards::Affine`: `x > (q-1)/2`
/// in the canonical (non-Montgomery) representation, where `q` is
/// the base-field modulus.
pub fn x_sign_is_negative(x: &Fr254) -> bool {
    let mut half = Fr254Modulus::Q;
    // half := q - 1
    let _ = half.sub_with_borrow(&ark_ff::BigInt::<4>::from(1u64));
    // half := (q - 1) / 2
    half.div2();
    x.into_bigint() > half
}

/// Compressed serialization: 32 LE bytes of `y` with the high bit of
/// byte 31 set to [`x_sign_is_negative`].
pub fn compress_point(p: &TePoint) -> [u8; 32] {
    let mut bytes = p.y.into_bigint().to_bytes_le();
    bytes.resize(32, 0);
    if x_sign_is_negative(&p.x) {
        bytes[31] |= 0x80;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

// ── helpers ───────────────────────────────────────────────────────

#[inline]
fn scalar_bit(limbs: &[u64], i: u64) -> bool {
    let limb = (i / 64) as usize;
    let off = (i % 64) as u32;
    if limb >= limbs.len() {
        false
    } else {
        ((limbs[limb] >> off) & 1) == 1
    }
}

/// Local re-export of BN254 Fr's modulus, used by the sign predicate
/// in [`x_sign_is_negative`]. Keeping this private avoids polluting
/// the public surface with arkworks types.
struct Fr254Modulus;
impl Fr254Modulus {
    const Q: ark_ff::BigInt<4> = <ark_bn254::Fr as ark_ff::PrimeField>::MODULUS;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_on_curve() {
        let curve = Curve::default_v1();
        assert!(TePoint::identity().is_on_curve(&curve));
    }

    #[test]
    fn generator_is_on_curve() {
        let curve = Curve::default_v1();
        let g = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        assert!(g.is_on_curve(&curve));
        assert!(!g.is_identity());
    }

    #[test]
    fn add_with_identity_is_identity_left() {
        let curve = Curve::default_v1();
        let g = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        let id = TePoint::identity();
        assert_eq!(add(&curve, &id, &g), g);
        assert_eq!(add(&curve, &g, &id), g);
    }

    #[test]
    fn scalar_mul_zero_is_identity() {
        let curve = Curve::default_v1();
        let g = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        assert!(scalar_mul(&curve, &g, &[0u64; 4]).is_identity());
    }

    #[test]
    fn scalar_mul_one_is_self() {
        let curve = Curve::default_v1();
        let g = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        assert_eq!(scalar_mul(&curve, &g, &[1u64, 0, 0, 0]), g);
    }

    #[test]
    fn scalar_mul_two_equals_double() {
        let curve = Curve::default_v1();
        let g = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        let dbl = double(&curve, &g);
        let via_mul = scalar_mul(&curve, &g, &[2u64, 0, 0, 0]);
        assert_eq!(dbl, via_mul);
    }

    #[test]
    fn default_v1_generator_is_in_subgroup() {
        let curve = Curve::default_v1();
        let g = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        assert!(is_in_subgroup(&curve, &g));
    }

    #[test]
    fn scalar_mul_matches_typed_backend_on_default_curve() {
        // Cross-check the runtime ladder against the audited typed
        // backend: for the default curve, k·G_runtime must equal the
        // affine of k·G_typed.
        use ark_ec::CurveGroup;
        use taceo_ark_babyjubjub::{EdwardsAffine, Fr as TacFr};

        let curve = Curve::default_v1();
        let g_runtime = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        let g_typed = EdwardsAffine::new_unchecked(curve.gx, curve.gy);

        let scalar_value = 0xDEAD_BEEF_u64;
        let runtime = scalar_mul(&curve, &g_runtime, &[scalar_value, 0, 0, 0]);

        let typed_scalar = TacFr::from(scalar_value);
        let typed = (g_typed * typed_scalar).into_affine();

        // Convert typed to TePoint coords for comparison.
        let typed_xy = TePoint {
            x: typed.x,
            y: typed.y,
        };
        assert_eq!(runtime, typed_xy);
    }

    #[test]
    fn x_sign_negative_threshold() {
        // (q-1)/2 + 1 must be flagged negative; (q-1)/2 must not.
        use ark_ff::PrimeField;
        let mut half = Fr254Modulus::Q;
        let _ = half.sub_with_borrow(&ark_ff::BigInt::<4>::from(1u64));
        half.div2();

        let half_fr = Fr254::from_bigint(half).unwrap();
        let one = Fr254::one();
        assert!(!x_sign_is_negative(&half_fr));
        assert!(x_sign_is_negative(&(half_fr + one)));
    }

    #[test]
    fn compress_point_round_trips_y_bytes() {
        let curve = Curve::default_v1();
        let g = TePoint {
            x: curve.gx,
            y: curve.gy,
        };
        let c = compress_point(&g);
        // The high bit may be set, but the lower 7 bits of byte 31
        // and all of bytes 0..31 must equal y in LE.
        let mut y_le = curve.gy.into_bigint().to_bytes_le();
        y_le.resize(32, 0);
        let masked_31 = c[31] & 0x7f;
        assert_eq!(&c[..31], &y_le[..31]);
        assert_eq!(masked_31, y_le[31]);
    }
}
