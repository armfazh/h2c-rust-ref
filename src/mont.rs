use redox_ecc::ellipticcurve::{EllipticCurve, MapToCurve};
use redox_ecc::field::{FromFactory, Sgn0Endianness};
use redox_ecc::instances::{GetCurve, MtCurveID, CURVE25519, CURVE448};
use redox_ecc::montgomery::{Curve, Ell2};

use crate::api::{Encoding, HashID, HashToCurve, MapID, Suite};

impl Suite<MtCurveID> {
    pub fn get(&self, dst: &[u8]) -> impl HashToCurve<E = Curve> {
        let dst = dst.to_vec();
        let e = self.curve.get();
        let f = e.get_field();
        let cofactor = e.new_scalar(e.get_cofactor());
        let map_to_curve: Box<dyn MapToCurve<E = Curve>> = match self.map {
            MapID::ELL2(z, s) => Box::new(Ell2::new(e, f.from(z), s)),
            _ => unimplemented!(),
        };
        Encoding {
            hash_to_field: Box::new(f),
            dst,
            map_to_curve,
            cofactor,
            h: self.h,
            l: self.l,
            ro: self.ro,
        }
    }
}

pub static CURVE25519_SHA256_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve25519-SHA256-ELL2-NU-",
    curve: CURVE25519,
    h: HashID::SHA256,
    map: MapID::ELL2(2, Sgn0Endianness::LittleEndian),
    l: 48,
    ro: false,
};
pub static CURVE25519_SHA256_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve25519-SHA256-ELL2-RO-",
    ro: true,
    ..CURVE25519_SHA256_ELL2_NU_
};

pub static CURVE25519_SHA512_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve25519-SHA512-ELL2-NU-",
    curve: CURVE25519,
    map: MapID::ELL2(2, Sgn0Endianness::LittleEndian),
    h: HashID::SHA512,
    l: 48,
    ro: false,
};
pub static CURVE25519_SHA512_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve25519-SHA512-ELL2-RO-",
    ro: true,
    ..CURVE25519_SHA512_ELL2_NU_
};

pub static CURVE448_SHA512_ELL2_NU_: Suite<MtCurveID> = Suite {
    name: "curve448-SHA512-ELL2-NU-",
    curve: CURVE448,
    map: MapID::ELL2(-1, Sgn0Endianness::LittleEndian),
    h: HashID::SHA512,
    l: 84,
    ro: false,
};
pub static CURVE448_SHA512_ELL2_RO_: Suite<MtCurveID> = Suite {
    name: "curve448-SHA512-ELL2-RO-",
    ro: true,
    ..CURVE448_SHA512_ELL2_NU_
};
