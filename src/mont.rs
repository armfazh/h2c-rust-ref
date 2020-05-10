use std::collections::HashMap;

use redox_ecc::ellipticcurve::{EllipticCurve, MapToCurve};
use redox_ecc::field::Sgn0Endianness;
use redox_ecc::instances::{GetCurve, MtCurveID, CURVE25519, CURVE448};
use redox_ecc::montgomery::{Curve, Ell2};
use redox_ecc::ops::FromFactory;

use crate::api::{Encoding, GetHashToCurve, HashID, HashToCurve, HashToField, MapID, Suite};
use crate::fp::{Expander, ExpanderXmd, FpHasher};
use crate::register_in_map;

impl GetHashToCurve for Suite<MtCurveID> {
    type E = Curve;
    fn get(&self, dst: &[u8]) -> Box<dyn HashToCurve<E = Self::E>> {
        let curve = self.curve.get();
        let f = curve.get_field();
        let cofactor = curve.new_scalar(curve.get_cofactor());
        let map_to_curve: Box<dyn MapToCurve<E = Curve>> = match self.map {
            MapID::ELL2(z, s) => Box::new(Ell2::new(curve.clone(), f.from(z), s)),
            _ => unimplemented!(),
        };
        let mut exp: Box<dyn Expander> = Box::new(ExpanderXmd {
            dst: dst.to_vec(),
            id: self.h,
        });
        exp.construct_dst_prime();
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
        CURVE448_XMDSHA512_ELL2_NU_,
        CURVE448_XMDSHA512_ELL2_RO_
    ]);
}

pub static CURVE25519_XMDSHA256_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve25519_XMD:SHA-256_ELL2_NU_",
    curve: CURVE25519,
    h: HashID::SHA256,
    map: MapID::ELL2(2, Sgn0Endianness::LittleEndian),
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
    map: MapID::ELL2(2, Sgn0Endianness::LittleEndian),
    h: HashID::SHA512,
    l: 48,
    ro: false,
};
pub static CURVE25519_XMDSHA512_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve25519_XMD:SHA-512_ELL2_RO_",
    ro: true,
    ..CURVE25519_XMDSHA512_ELL2_NU_
};

pub static CURVE448_XMDSHA512_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve448_XMD:SHA-512_ELL2_NU_",
    curve: CURVE448,
    map: MapID::ELL2(-1, Sgn0Endianness::LittleEndian),
    h: HashID::SHA512,
    l: 84,
    ro: false,
};
pub static CURVE448_XMDSHA512_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve448_XMD:SHA-512_ELL2_RO_",
    ro: true,
    ..CURVE448_XMDSHA512_ELL2_NU_
};
