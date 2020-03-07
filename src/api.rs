use redox_ecc::ellipticcurve::{EllipticCurve, MapToCurve};
use redox_ecc::field::{Field, Sgn0Endianness};
use redox_ecc::instances::GetCurve;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashID {
    SHA256,
    SHA384,
    SHA512,
}

/// HashToField hashes a string msg of any length into an element of a field F.
/// This function is parametrized by a cryptographic hash function.
pub trait HashToField {
    type F: Field;
    fn hash(&self, h: HashID, msg: &[u8], dst: &[u8], ctr: u8, l: usize)
        -> <Self::F as Field>::Elt;
}

/// HashToCurve is a function that outputs a point on an elliptic curve from an
/// arbitrary string.
pub trait HashToCurve {
    type E: EllipticCurve;
    fn is_random_oracle(&self) -> bool;
    fn hash(&self, msg: &[u8]) -> <Self::E as EllipticCurve>::Point;
}

pub(crate) struct Encoding<EE>
where
    EE: EllipticCurve,
{
    pub(crate) dst: Vec<u8>,
    pub(crate) h: HashID,
    pub(crate) map_to_curve: Box<dyn MapToCurve<E = EE> + 'static>,
    pub(crate) hash_to_field: Box<dyn HashToField<F = <EE as EllipticCurve>::F> + 'static>,
    pub(crate) cofactor: <EE as EllipticCurve>::Scalar,
    pub(crate) l: usize,
    pub(crate) ro: bool,
}

impl<EE> HashToCurve for Encoding<EE>
where
    EE: EllipticCurve,
{
    type E = EE;
    #[inline]
    fn is_random_oracle(&self) -> bool {
        self.ro
    }
    fn hash(&self, msg: &[u8]) -> <Self::E as EllipticCurve>::Point {
        let p = if self.ro {
            let u0 = self.hash_to_field.hash(self.h, msg, &self.dst, 0u8, self.l);
            let u1 = self.hash_to_field.hash(self.h, msg, &self.dst, 1u8, self.l);
            let p0 = self.map_to_curve.map(u0);
            let p1 = self.map_to_curve.map(u1);
            p0 + p1
        } else {
            let u = self.hash_to_field.hash(self.h, msg, &self.dst, 2u8, self.l);
            self.map_to_curve.map(u)
        };
        p * &self.cofactor
    }
}

#[derive(Copy, Clone)]
pub enum MapID {
    SSWU(i32, Sgn0Endianness),
    SVDW(i32, Sgn0Endianness),
    ELL2(i32, Sgn0Endianness),
}

#[derive(Copy, Clone)]
pub struct Suite<T>
where
    T: GetCurve,
{
    pub(super) curve: T,
    pub(super) name: &'static str,
    pub(super) map: MapID,
    pub(super) h: HashID,
    pub(super) l: usize,
    pub(super) ro: bool,
}

impl<T> std::fmt::Display for Suite<T>
where
    T: GetCurve,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}
