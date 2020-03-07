use redox_ecc::ellipticcurve::{EllipticCurve, MapToCurve};
use redox_ecc::field::{FromFactory, Sgn0Endianness};
use redox_ecc::instances::{GetCurve, WeCurveID, P256, P384, P521, SECP256K1};
use redox_ecc::weierstrass::{Curve, SSWU, SVDW};

use crate::api::{Encoding, HashID, HashToCurve, MapID, Suite};

impl Suite<WeCurveID> {
    pub fn get(&self, dst: &[u8]) -> impl HashToCurve<E = Curve> {
        let dst = dst.to_vec();
        let e = self.curve.get();
        let f = e.get_field();
        let cofactor = e.new_scalar(e.get_cofactor());
        let map_to_curve: Box<dyn MapToCurve<E = Curve>> = match self.map {
            MapID::SSWU(z, s) => Box::new(SSWU::new(e, f.from(z), s)),
            MapID::SVDW(z, s) => Box::new(SVDW::new(e, f.from(z), s)),
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

pub static P256_SHA256_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "P256-SHA256-SSWU-NU-",
    curve: P256,
    h: HashID::SHA256,
    map: MapID::SSWU(-10, Sgn0Endianness::LittleEndian),
    l: 48,
    ro: false,
};
pub static P256_SHA256_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "P256-SHA256-SSWU-RO-",
    ro: true,
    ..P256_SHA256_SSWU_NU_
};

pub static P256_SHA256_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "P256-SHA256-SVDW-NU-",
    curve: P256,
    h: HashID::SHA256,
    map: MapID::SVDW(-3, Sgn0Endianness::LittleEndian),
    l: 48,
    ro: false,
};
pub static P256_SHA256_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "P256-SHA256-SVDW-RO-",
    ro: true,
    ..P256_SHA256_SVDW_NU_
};

pub static P384_SHA512_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "P384-SHA512-SSWU-NU-",
    curve: P384,
    h: HashID::SHA512,
    map: MapID::SSWU(-12, Sgn0Endianness::LittleEndian),
    l: 72,
    ro: false,
};
pub static P384_SHA512_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "P384-SHA512-SSWU-RO-",
    ro: true,
    ..P384_SHA512_SSWU_NU_
};

pub static P384_SHA512_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "P384-SHA512-SVDW-NU-",
    curve: P384,
    h: HashID::SHA512,
    map: MapID::SVDW(-1, Sgn0Endianness::LittleEndian),
    l: 72,
    ro: false,
};
pub static P384_SHA512_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "P384-SHA512-SVDW-RO-",
    ro: true,
    ..P384_SHA512_SVDW_NU_
};

pub static P521_SHA512_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "P521-SHA512-SSWU-NU-",
    curve: P521,
    h: HashID::SHA512,
    map: MapID::SSWU(-4, Sgn0Endianness::LittleEndian),
    l: 96,
    ro: false,
};
pub static P521_SHA512_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "P521-SHA512-SSWU-RO-",
    ro: true,
    ..P521_SHA512_SSWU_NU_
};

pub static P521_SHA512_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "P521-SHA512-SVDW-NU-",
    curve: P521,
    h: HashID::SHA512,
    map: MapID::SVDW(1, Sgn0Endianness::LittleEndian),
    l: 96,
    ro: false,
};
pub static P521_SHA512_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "P521-SHA512-SVDW-RO-",
    ro: true,
    ..P521_SHA512_SVDW_NU_
};

pub static SECP256K1_SHA256_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "secp256k1-SHA256-SSWU-NU-",
    curve: SECP256K1,
    map: MapID::SSWU(-11, Sgn0Endianness::LittleEndian),
    h: HashID::SHA256,
    l: 48,
    ro: false,
};
pub static SECP256K1_SHA256_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "secp256k1-SHA256-SSWU-RO-",
    ro: true,
    ..SECP256K1_SHA256_SSWU_NU_
};
