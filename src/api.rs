use redox_ecc::ellipticcurve::{EllipticCurve, MapToCurve};
use redox_ecc::field::Field;
use redox_ecc::instances::GetCurve;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashID {
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum XofID {
    SHAKE128,
    SHAKE256,
}

/// HashToField hashes a string msg of any length into an element of a field F.
pub trait HashToField {
    type F: Field;
    fn hash(&self, msg: &[u8], count: usize) -> Vec<<Self::F as Field>::Elt>;
}

pub trait GetHashToCurve {
    type E: EllipticCurve;
    fn get(&self, dst: &[u8]) -> Box<dyn HashToCurve<E = Self::E> + 'static>;
}
/// HashToCurve is a function that outputs a point on an elliptic curve from an
/// arbitrary string.
pub trait HashToCurve {
    type E: EllipticCurve;
    fn get_curve(&self) -> &Self::E;
    fn is_random_oracle(&self) -> bool;
    fn hash(&self, msg: &[u8]) -> <Self::E as EllipticCurve>::Point;
}

pub(crate) struct Encoding<EE>
where
    EE: EllipticCurve,
{
    pub(crate) curve: EE,
    pub(crate) map_to_curve: Box<dyn MapToCurve<E = EE> + 'static>,
    pub(crate) hash_to_field: Box<dyn HashToField<F = <EE as EllipticCurve>::F> + 'static>,
    pub(crate) cofactor: <EE as EllipticCurve>::Scalar,
    pub(crate) ro: bool,
}

impl<EE> HashToCurve for Encoding<EE>
where
    EE: EllipticCurve + Clone,
{
    type E = EE;
    #[inline]
    fn get_curve(&self) -> &Self::E {
        &self.curve
    }
    #[inline]
    fn is_random_oracle(&self) -> bool {
        self.ro
    }
    fn hash(&self, msg: &[u8]) -> <Self::E as EllipticCurve>::Point {
        let p = if self.ro {
            let u = self.hash_to_field.hash(msg, 2);
            let p0 = self.map_to_curve.map(&u[0]);
            let p1 = self.map_to_curve.map(&u[1]);
            p0 + p1
        } else {
            let u = self.hash_to_field.hash(msg, 1);
            self.map_to_curve.map(&u[0])
        };
        p * &self.cofactor
    }
}

#[derive(Copy, Clone)]
pub enum MapID {
    SSWU(i32),
    SSWUAB0(i32),
    SVDW(i32),
    ELL2(i32),
}

#[derive(Copy, Clone)]
pub enum ExpID {
    XMD(HashID),
    XOF(XofID),
}

#[derive(Copy, Clone)]
pub struct Suite<T>
where
    T: GetCurve,
{
    pub(super) curve: T,
    pub(super) name: &'static str,
    pub(super) map: MapID,
    pub(super) exp: ExpID,
    pub(super) k: usize,
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
