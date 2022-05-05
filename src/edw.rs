use std::collections::HashMap;

use redox_ecc::edwards::{Curve as EdCurve, Ell2};
use redox_ecc::ellipticcurve::{EllipticCurve, MapToCurve, RationalMap};
use redox_ecc::instances::{
    edwards25519_to_curve25519, edwards448_to_curve448, EdCurveID, GetCurve, EDWARDS25519,
    EDWARDS448,
};
use redox_ecc::montgomery::Curve as MtCurve;
use redox_ecc::ops::FromFactory;

use crate::api::{
    Encoding, ExpID, GetHashToCurve, HashID, HashToCurve, HashToField, MapID, Suite, XofID,
};
use crate::expander::get_expander;
use crate::fp::FpHasher;
use crate::register_in_map;

impl GetHashToCurve for Suite<EdCurveID> {
    type E = EdCurve;
    fn get(&self, dst: &[u8]) -> Box<dyn HashToCurve<E = Self::E>> {
        let curve = self.curve.get();
        let f = curve.get_field();
        let cofactor = curve.new_scalar(curve.get_cofactor());
        let ratmap: Option<Box<dyn RationalMap<E0 = EdCurve, E1 = MtCurve>>> =
            if self.curve == EDWARDS25519 {
                Some(Box::new(edwards25519_to_curve25519()))
            } else if self.curve == EDWARDS448 {
                Some(Box::new(edwards448_to_curve448()))
            } else {
                None
            };
        let map_to_curve: Box<dyn MapToCurve<E = EdCurve>> = match self.map {
            MapID::ELL2(z) => Box::new(Ell2::new(curve.clone(), f.from(z), ratmap)),
            _ => unimplemented!(),
        };
        let exp = get_expander(self.exp, dst, self.k);
        let hash_to_field: Box<dyn HashToField<F = <EdCurve as EllipticCurve>::F>> =
            Box::new(FpHasher { f, exp, l: self.l });
        Box::new(Encoding {
            curve,
            hash_to_field,
            map_to_curve,
            cofactor,
            ro: self.ro,
        })
    }
}

lazy_static! {
    pub static ref SUITES_EDWARDS: HashMap<String, Suite<EdCurveID>> = register_in_map!([
        EDWARDS25519_XMDSHA256_ELL2_NU_,
        EDWARDS25519_XMDSHA256_ELL2_RO_,
        EDWARDS25519_XMDSHA512_ELL2_NU_,
        EDWARDS25519_XMDSHA512_ELL2_RO_,
        EDWARDS448_XOFSHAKE256_ELL2_NU_,
        EDWARDS448_XOFSHAKE256_ELL2_RO_
    ]);
}

pub static EDWARDS25519_XMDSHA256_ELL2_NU_: Suite<EdCurveID> = Suite {
    name: "edwards25519_XMD:SHA-256_ELL2_NU_",
    curve: EDWARDS25519,
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    map: MapID::ELL2(2),
    l: 48,
    ro: false,
};
pub static EDWARDS25519_XMDSHA256_ELL2_RO_: Suite<EdCurveID> = Suite {
    name: "edwards25519_XMD:SHA-256_ELL2_RO_",
    ro: true,
    ..EDWARDS25519_XMDSHA256_ELL2_NU_
};

pub static EDWARDS25519_XMDSHA512_ELL2_NU_: Suite<EdCurveID> = Suite {
    name: "edwards25519_XMD:SHA-512_ELL2_NU_",
    curve: EDWARDS25519,
    map: MapID::ELL2(2),
    k: 128,
    exp: ExpID::XMD(HashID::SHA512),
    l: 48,
    ro: false,
};
pub static EDWARDS25519_XMDSHA512_ELL2_RO_: Suite<EdCurveID> = Suite {
    name: "edwards25519_XMD:SHA-512_ELL2_RO_",
    ro: true,
    ..EDWARDS25519_XMDSHA512_ELL2_NU_
};

pub static EDWARDS448_XOFSHAKE256_ELL2_NU_: Suite<EdCurveID> = Suite {
    name: "edwards448_XOF:SHAKE256_ELL2_NU_",
    curve: EDWARDS448,
    map: MapID::ELL2(-1),
    k: 224,
    exp: ExpID::XOF(XofID::SHAKE256),
    l: 84,
    ro: false,
};
pub static EDWARDS448_XOFSHAKE256_ELL2_RO_: Suite<EdCurveID> = Suite {
    name: "edwards448_XOF:SHAKE256_ELL2_RO_",
    ro: true,
    ..EDWARDS448_XOFSHAKE256_ELL2_NU_
};
