use std::collections::HashMap;

use redox_ecc::ellipticcurve::{EllipticCurve, Isogeny, MapToCurve};
use redox_ecc::instances::{
    get_isogeny_bls12381g1, get_isogeny_secp256k1, GetCurve, WeCurveID, BLS12381G1, P256, P384,
    P521, SECP256K1,
};
use redox_ecc::ops::FromFactory;
use redox_ecc::weierstrass::{Curve, SSWU, SSWUAB0, SVDW};

use crate::api::{
    Encoding, ExpID, GetHashToCurve, HashID, HashToCurve, HashToField, MapID, Suite, XofID,
};
use crate::expander::get_expander;
use crate::fp::FpHasher;
use crate::register_in_map;

impl GetHashToCurve for Suite<WeCurveID> {
    type E = Curve;
    fn get(&self, dst: &[u8]) -> Box<dyn HashToCurve<E = Self::E>> {
        let curve = self.curve.get();
        let f = curve.get_field();
        let cofactor = curve.new_scalar(curve.get_cofactor());
        let map_to_curve: Box<dyn MapToCurve<E = Curve>> = match self.map {
            MapID::SSWUAB0(z) => {
                let iso: Box<dyn Isogeny<E0 = Curve, E1 = Curve>> = if self.curve == SECP256K1 {
                    Box::new(get_isogeny_secp256k1())
                } else if self.curve == BLS12381G1 {
                    Box::new(get_isogeny_bls12381g1())
                } else {
                    unimplemented!()
                };
                Box::new(SSWUAB0::new(curve.clone(), f.from(z), iso))
            }
            MapID::SSWU(z) => Box::new(SSWU::new(curve.clone(), f.from(z))),
            MapID::SVDW(z) => Box::new(SVDW::new(curve.clone(), f.from(z))),
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
    pub static ref SUITES_WEIERSTRASS: HashMap<String, Suite<WeCurveID>> = register_in_map!([
        P256_XMDSHA256_SSWU_NU_,
        P256_XMDSHA256_SSWU_RO_,
        P256_XMDSHAKE128_SSWU_NU_,
        P256_XMDSHAKE128_SSWU_RO_,
        P256_XMDSHA256_SVDW_NU_,
        P256_XMDSHA256_SVDW_RO_,
        P384_XMDSHA384_SSWU_NU_,
        P384_XMDSHA384_SSWU_RO_,
        P384_XMDSHA384_SVDW_NU_,
        P384_XMDSHA384_SVDW_RO_,
        P521_XMDSHA512_SSWU_NU_,
        P521_XMDSHA512_SSWU_RO_,
        P521_XMDSHA512_SVDW_NU_,
        P521_XMDSHA512_SVDW_RO_,
        SECP256K1_XMDSHA256_SSWU_RO_,
        SECP256K1_XMDSHA256_SSWU_NU_,
        SECP256K1_XMDSHA256_SVDW_RO_,
        SECP256K1_XMDSHA256_SVDW_NU_,
        BLS12381G1_XMDSHA256_SSWU_NU_,
        BLS12381G1_XMDSHA256_SSWU_RO_,
        BLS12381G1_XMDSHA256_SVDW_RO_,
        BLS12381G1_XMDSHA256_SVDW_NU_
    ]);
}

pub static P256_XMDSHA256_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "P256_XMD:SHA-256_SSWU_NU_",
    curve: P256,
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    map: MapID::SSWU(-10),
    l: 48,
    ro: false,
};
pub static P256_XMDSHA256_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "P256_XMD:SHA-256_SSWU_RO_",
    ro: true,
    ..P256_XMDSHA256_SSWU_NU_
};

pub static P256_XMDSHAKE128_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "P256_XMD:SHAKE128_SSWU_NU_",
    curve: P256,
    k: 128,
    exp: ExpID::XOF(XofID::SHAKE128),
    map: MapID::SSWU(-10),
    l: 48,
    ro: false,
};
pub static P256_XMDSHAKE128_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "P256_XMD:SHAKE128_SSWU_RO_",
    ro: true,
    ..P256_XMDSHAKE128_SSWU_NU_
};

pub static P256_XMDSHA256_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "P256_XMD:SHA-256_SVDW_NU_",
    curve: P256,
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    map: MapID::SVDW(-3),
    l: 48,
    ro: false,
};
pub static P256_XMDSHA256_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "P256_XMD:SHA-256_SVDW_RO_",
    ro: true,
    ..P256_XMDSHA256_SVDW_NU_
};

pub static P384_XMDSHA384_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "P384_XMD:SHA-384_SSWU_NU_",
    curve: P384,
    k: 192,
    exp: ExpID::XMD(HashID::SHA384),
    map: MapID::SSWU(-12),
    l: 72,
    ro: false,
};
pub static P384_XMDSHA384_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "P384_XMD:SHA-384_SSWU_RO_",
    ro: true,
    ..P384_XMDSHA384_SSWU_NU_
};

pub static P384_XMDSHA384_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "P384_XMD:SHA-384_SVDW_NU_",
    curve: P384,
    k: 192,
    exp: ExpID::XMD(HashID::SHA384),
    map: MapID::SVDW(-1),
    l: 72,
    ro: false,
};
pub static P384_XMDSHA384_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "P384_XMD:SHA-384_SVDW_RO_",
    ro: true,
    ..P384_XMDSHA384_SVDW_NU_
};

pub static P521_XMDSHA512_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "P521_XMD:SHA-512_SSWU_NU_",
    curve: P521,
    k: 256,
    exp: ExpID::XMD(HashID::SHA512),
    map: MapID::SSWU(-4),
    l: 98,
    ro: false,
};
pub static P521_XMDSHA512_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "P521_XMD:SHA-512_SSWU_RO_",
    ro: true,
    ..P521_XMDSHA512_SSWU_NU_
};

pub static P521_XMDSHA512_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "P521_XMD:SHA-512_SVDW_NU_",
    curve: P521,
    k: 256,
    exp: ExpID::XMD(HashID::SHA512),
    map: MapID::SVDW(1),
    l: 98,
    ro: false,
};
pub static P521_XMDSHA512_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "P521_XMD:SHA-512_SVDW_RO_",
    ro: true,
    ..P521_XMDSHA512_SVDW_NU_
};

pub static SECP256K1_XMDSHA256_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "secp256k1_XMD:SHA-256_SSWU_NU_",
    curve: SECP256K1,
    map: MapID::SSWUAB0(-11),
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    l: 48,
    ro: false,
};
pub static SECP256K1_XMDSHA256_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "secp256k1_XMD:SHA-256_SSWU_RO_",
    ro: true,
    ..SECP256K1_XMDSHA256_SSWU_NU_
};

pub static SECP256K1_XMDSHA256_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "secp256k1_XMD:SHA-256_SVDW_NU_",
    curve: SECP256K1,
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    map: MapID::SVDW(1),
    l: 48,
    ro: false,
};
pub static SECP256K1_XMDSHA256_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "secp256k1_XMD:SHA-256_SVDW_RO_",
    ro: true,
    ..SECP256K1_XMDSHA256_SVDW_NU_
};

pub static BLS12381G1_XMDSHA256_SSWU_NU_: Suite<WeCurveID> = Suite {
    name: "BLS12381G1_XMD:SHA-256_SSWU_NU_",
    curve: BLS12381G1,
    map: MapID::SSWUAB0(11),
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    l: 64,
    ro: false,
};
pub static BLS12381G1_XMDSHA256_SSWU_RO_: Suite<WeCurveID> = Suite {
    name: "BLS12381G1_XMD:SHA-256_SSWU_RO_",
    ro: true,
    ..BLS12381G1_XMDSHA256_SSWU_NU_
};

pub static BLS12381G1_XMDSHA256_SVDW_NU_: Suite<WeCurveID> = Suite {
    name: "BLS12381G1_XMD:SHA-256_SVDW_NU_",
    curve: BLS12381G1,
    k: 128,
    exp: ExpID::XMD(HashID::SHA256),
    map: MapID::SVDW(-3),
    l: 64,
    ro: false,
};
pub static BLS12381G1_XMDSHA256_SVDW_RO_: Suite<WeCurveID> = Suite {
    name: "BLS12381G1_XMD:SHA-256_SVDW_RO_",
    ro: true,
    ..BLS12381G1_XMDSHA256_SVDW_NU_
};
