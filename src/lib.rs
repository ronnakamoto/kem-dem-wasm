//! kem-dem-wasm — production-grade WebAssembly bindings for two
//! complementary hybrid public-key encryption schemes:
//!
//! 1. **HPKE (RFC 9180)** with per-field manifest binding for safe
//!    field-level encryption of arbitrary JS records. Exposed as
//!    [`KemDem`].
//! 2. **ZK-friendly BabyJubJub KEM-DEM** over the BN254 scalar field,
//!    with an optional Poseidon-MAC authenticated variant. Exposed as
//!    [`ZkEncryptor`].
//!
//! The crate is split across small, focused modules:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │ lib.rs        — crate root: lints, panic hook, re-exports │
//! ├──────────────────────────────────────────────────────────┤
//! │ hpke_api      — KemDem / KeyPair / EncryptedPackage /     │
//! │                 EncryptedBlob (WASM-facing HPKE façade)   │
//! │ kem           — thin wrapper around the `hpke` crate      │
//! │ derive        — deterministic X25519 derivation from      │
//! │                 Ethereum wallet material                  │
//! │ zk_api        — ZkEncryptor (WASM-facing ZK façade)       │
//! │ kemdem_funcs  — BabyJubJub KEM-DEM primitives             │
//! │ hex_util      — shared Fr/scalar hex parsers + RNG helper │
//! │ error         — CryptoError + conversions                 │
//! └──────────────────────────────────────────────────────────┘
//! ```

// Production-grade lints. Any `unsafe` usage in this crate would
// invalidate the security guarantees we make, so forbid it outright.
// `unused_must_use` catches dropped Results (e.g. an ignored AEAD
// verification result would be catastrophic).
#![forbid(unsafe_code)]
#![deny(unused_must_use, unreachable_patterns, rust_2018_idioms)]
#![warn(clippy::all)]

pub mod curve;
mod derive;
mod error;
mod hex_util;
mod hpke_api;
mod kem;
pub mod kemdem_functions;
mod runtime_kemdem;
mod te_arith;
mod zk_api;

// Re-export the WASM-facing types at the crate root so `wasm-bindgen`
// keeps emitting them under their existing JS names — splitting the
// implementation across modules must not change the public API.
pub use curve::ZkCurve;
pub use hpke_api::{
    EncryptedBlob, EncryptedPackage, KemDem, KeyPair, MAX_FIELD_COUNT, MAX_FIELD_VALUE_LEN,
};
pub use zk_api::ZkEncryptor;

use wasm_bindgen::prelude::*;

/// Initialize the panic hook for better debugging in the browser
/// console. Called automatically by the wasm-bindgen runtime on first
/// import (see `#[wasm_bindgen(start)]`).
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}
