use std::collections::HashMap;

use redox_ecc::ellipticcurve::{EllipticCurve, MapToCurve};
use redox_ecc::instances::{GetCurve, MtCurveID, CURVE25519, CURVE448};
use redox_ecc::montgomery::{Curve, Ell2};
use redox_ecc::ops::FromFactory;

use crate::api::{
    Encoding, ExpID, GetHashToCurve, HashID, HashToCurve, HashToField, MapID, Suite, XofID,
};
use crate::expander::get_expander;
use crate::fp::FpHasher;
use crate::register_in_map;

impl GetHashToCurve for Suite<MtCurveID> {
    type E = Curve;
    fn get(&self, dst: &[u8]) -> Box<dyn HashToCurve<E = Self::E>> {
        let curve = self.curve.get();
        let f = curve.get_field();
        let cofactor = curve.new_scalar(curve.get_cofactor());
        let map_to_curve: Box<dyn MapToCurve<E = Curve>> = match self.map {
            MapID::ELL2(z) => Box::new(Ell2::new(curve.clone(), f.from(z))),
            _ => unimplemented!(),
        };
        let exp = get_expander(self.exp, dst, self.k);
        let hash_to_field: Box<dyn HashToField<F = <Curve as EllipticCurve>::F>> =
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
    pub static ref SUITES_MONTGOMERY: HashMap<String, Suite<MtCurveID>> = register_in_map!([
        CURVE25519_XMDSHA256_ELL2_NU_,
        CURVE25519_XMDSHA256_ELL2_RO_,
        CURVE25519_XMDSHA512_ELL2_NU_,
        CURVE25519_XMDSHA512_ELL2_RO_,
        CURVE448_XOFSHAKE256_ELL2_NU_,
        CURVE448_XOFSHAKE256_ELL2_RO_
    ]);
}

pub static CURVE25519_XMDSHA256_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve25519_XMD:SHA-256_ELL2_NU_",
    curve: CURVE25519,
    map: MapID::ELL2(2),
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    l: 48,
    ro: false,
};
pub static CURVE25519_XMDSHA256_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve25519_XMD:SHA-256_ELL2_RO_",
    ro: true,
    ..CURVE25519_XMDSHA256_ELL2_NU_
};

pub static CURVE25519_XMDSHA512_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve25519_XMD:SHA-512_ELL2_NU_",
    curve: CURVE25519,
    map: MapID::ELL2(2),
    k: 128,
    exp: ExpID::XMD(HashID::SHA512),
    l: 48,
    ro: false,
};
pub static CURVE25519_XMDSHA512_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve25519_XMD:SHA-512_ELL2_RO_",
    ro: true,
    ..CURVE25519_XMDSHA512_ELL2_NU_
};

pub static CURVE448_XOFSHAKE256_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve448_XOF:SHAKE256_ELL2_NU_",
    curve: CURVE448,
    map: MapID::ELL2(-1),
    k: 224,
    exp: ExpID::XOF(XofID::SHAKE256),
    l: 84,
    ro: false,
};
pub static CURVE448_XOFSHAKE256_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve448_XOF:SHAKE256_ELL2_RO_",
    ro: true,
    ..CURVE448_XOFSHAKE256_ELL2_NU_
};
