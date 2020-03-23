//! `h2c_rust_ref` is a reference implementation of hash to curve methods.
//!
//! # Warning
//!
//! This implementation is **not** protected against any kind of attack, including
//! side-channel attacks. Do not use this code for securing any application.
//!
//! # Hash to Curve
//!
//! ```
//!  use h2c_rust_ref::GetHashToCurve;
//!  use h2c_rust_ref::{EDWARDS25519_SHA512_EDELL2_RO_,P256_SHA256_SSWU_RO_};
//!  let msg = b"Message string";
//!  let dst = b"Domain separation tag";
//!
//!  let suite = P256_SHA256_SSWU_RO_;
//!  let h = suite.get(dst);
//!  let mut p = h.hash(msg);
//!  p.normalize();
//!  println!("enc: {} {}", suite, p);
//!
//!  let suite = EDWARDS25519_SHA512_EDELL2_RO_;
//!  let h = suite.get(dst);
//!  let mut p = h.hash(msg);
//!  p.normalize();
//!  println!("enc: {} {}", suite, p);
//! ```
//!

#[macro_use]
extern crate lazy_static;

mod macros;

mod api;
mod edw;
mod fp;
mod mont;
mod weier;

pub use crate::api::{GetHashToCurve, HashToCurve, HashToField, Suite};
pub use crate::edw::{
    EDWARDS25519_SHA256_EDELL2_NU_, EDWARDS25519_SHA256_EDELL2_RO_, EDWARDS25519_SHA512_EDELL2_NU_,
    EDWARDS25519_SHA512_EDELL2_RO_, EDWARDS448_SHA512_EDELL2_NU_, EDWARDS448_SHA512_EDELL2_RO_,
    SUITES_EDWARDS,
};
pub use crate::mont::{
    CURVE25519_SHA256_ELL2_NU_, CURVE25519_SHA256_ELL2_RO_, CURVE25519_SHA512_ELL2_NU_,
    CURVE25519_SHA512_ELL2_RO_, CURVE448_SHA512_ELL2_NU_, CURVE448_SHA512_ELL2_RO_,
    SUITES_MONTGOMERY,
};
pub use crate::weier::{
    BLS12381G1_SHA256_SSWU_NU_, BLS12381G1_SHA256_SSWU_RO_, BLS12381G1_SHA256_SVDW_NU_,
    BLS12381G1_SHA256_SVDW_RO_, P256_SHA256_SSWU_NU_, P256_SHA256_SSWU_RO_, P256_SHA256_SVDW_NU_,
    P256_SHA256_SVDW_RO_, P384_SHA512_SSWU_NU_, P384_SHA512_SSWU_RO_, P384_SHA512_SVDW_NU_,
    P384_SHA512_SVDW_RO_, P521_SHA512_SSWU_NU_, P521_SHA512_SSWU_RO_, P521_SHA512_SVDW_NU_,
    P521_SHA512_SVDW_RO_, SECP256K1_SHA256_SSWU_NU_, SECP256K1_SHA256_SSWU_RO_,
    SECP256K1_SHA256_SVDW_NU_, SECP256K1_SHA256_SVDW_RO_, SUITES_WEIERSTRASS,
};
