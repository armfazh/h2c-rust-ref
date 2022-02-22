use atomic_refcell::AtomicRefCell;
use digest::{DynDigest, ExtendableOutput, Update};
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Shake128, Shake256};

use crate::api::{ExpID, HashID, XofID};

pub trait Expander {
    fn construct_dst_prime(&self) -> Vec<u8>;
    fn expand(&self, msg: &[u8], length: usize) -> Vec<u8>;
}
const MAX_DST_LENGTH: usize = 255;

lazy_static! {
static ref LONG_DST_PREFIX: Vec<u8> = vec![
    //'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-',
    0x48, 0x32, 0x43, 0x2d, 0x4f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x5a, 0x45, 0x2d, 0x44, 0x53, 0x54, 0x2d,
];
}

pub(super) struct ExpanderXof<T: Update + Clone + ExtendableOutput> {
    pub(super) xofer: T,
    pub(super) dst: Vec<u8>,
    pub(super) k: usize,
    pub(super) dst_prime: AtomicRefCell<Option<Vec<u8>>>,
}

impl<T: Update + Clone + ExtendableOutput> Expander for ExpanderXof<T> {
    fn construct_dst_prime(&self) -> Vec<u8> {
        let mut dst_prime = if self.dst.len() > MAX_DST_LENGTH {
            let mut xofer = self.xofer.clone();
            xofer.update(&LONG_DST_PREFIX.clone());
            xofer.update(&self.dst);
            xofer.finalize_boxed((2 * self.k + 7) >> 3).to_vec()
        } else {
            self.dst.clone()
        };
        dst_prime.push(dst_prime.len() as u8);
        dst_prime
    }
    fn expand(&self, msg: &[u8], n: usize) -> Vec<u8> {
        let dst_prime = self
            .dst_prime
            .borrow_mut()
            .get_or_insert(self.construct_dst_prime())
            .clone();

        if n > (u16::MAX as usize) || dst_prime.len() > (u8::MAX as usize) {
            panic!("requested too many bytes")
        }

        let lib_str = &[((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8];

        let mut xofer = self.xofer.clone();
        xofer.update(msg);
        xofer.update(lib_str);
        xofer.update(&dst_prime);
        xofer.finalize_boxed(n).to_vec()
    }
}

pub(super) struct ExpanderXmd<T: DynDigest + Clone> {
    pub(super) hasher: T,
    pub(super) dst: Vec<u8>,
    pub(super) block_size: usize,
    pub(super) dst_prime: AtomicRefCell<Option<Vec<u8>>>,
}

impl<T: DynDigest + Clone> Expander for ExpanderXmd<T> {
    fn construct_dst_prime(&self) -> Vec<u8> {
        let mut dst_prime = if self.dst.len() > MAX_DST_LENGTH {
            let mut hasher = self.hasher.clone();
            hasher.update(&LONG_DST_PREFIX);
            hasher.update(&self.dst);
            hasher.finalize_reset().to_vec()
        } else {
            self.dst.clone()
        };
        dst_prime.push(dst_prime.len() as u8);
        dst_prime
    }
    fn expand(&self, msg: &[u8], n: usize) -> Vec<u8> {
        let mut hasher = self.hasher.clone();
        let b_len = hasher.output_size();
        let ell = (n + (b_len - 1)) / b_len;
        let dst_prime = self
            .dst_prime
            .borrow_mut()
            .get_or_insert(self.construct_dst_prime())
            .clone();

        if ell > (u8::MAX as usize)
            || n > (u16::MAX as usize)
            || dst_prime.len() > (u8::MAX as usize)
        {
            panic!("requested too many bytes")
        }

        let z_pad: Vec<u8> = vec![0; self.block_size];
        let lib_str = &[((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8];

        hasher.reset();
        hasher.update(&z_pad);
        hasher.update(msg);
        hasher.update(lib_str);
        hasher.update(&[0u8]);
        hasher.update(&dst_prime);
        let b0 = hasher.finalize_reset();

        hasher.reset();
        hasher.update(&b0);
        hasher.update(&[1u8]);
        hasher.update(&dst_prime);
        let mut bi = hasher.finalize_reset();

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&bi);
        for i in 2..(ell + 1) {
            hasher.reset();
            hasher.update(&xor(&bi, &b0));
            hasher.update(&[i as u8]);
            hasher.update(&dst_prime);
            bi = hasher.finalize_reset();
            pseudo.extend_from_slice(&bi);
        }
        pseudo[0..n].to_vec()
    }
}

fn xor<'a>(x: &'a [u8], y: &'a [u8]) -> Vec<u8> {
    let mut z = vec![0; x.len()];
    for i in 0..x.len() {
        z[i] = x[i] ^ y[i];
    }
    z.to_vec()
}

pub fn get_expander(id: ExpID, _dst: &[u8], k: usize) -> Box<dyn Expander> {
    let dst_prime = AtomicRefCell::new(None);
    let dst = _dst.to_vec();

    match id {
        ExpID::XMD(h) => match h {
            HashID::SHA256 => Box::new(ExpanderXmd {
                hasher: Sha256::default(),
                block_size: 64,
                dst,
                dst_prime,
            }),
            HashID::SHA384 => Box::new(ExpanderXmd {
                hasher: Sha384::default(),
                block_size: 128,
                dst,
                dst_prime,
            }),
            HashID::SHA512 => Box::new(ExpanderXmd {
                hasher: Sha512::default(),
                block_size: 128,
                dst,
                dst_prime,
            }),
        },
        ExpID::XOF(x) => match x {
            XofID::SHAKE128 => Box::new(ExpanderXof {
                xofer: Shake128::default(),
                k,
                dst,
                dst_prime,
            }),
            XofID::SHAKE256 => Box::new(ExpanderXof {
                xofer: Shake256::default(),
                k,
                dst,
                dst_prime,
            }),
        },
    }
}

#[cfg(test)]
mod tests;
