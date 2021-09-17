use atomic_refcell::AtomicRefCell;
use digest::{DynDigest, ExtendableOutput, Update};
use sha2::{Digest as sha2_digest, Sha256, Sha512};
use sha3::Shake128;

use crate::api::{HashID, XofID};

pub trait Expander {
    fn construct_dst_prime(&self) -> Vec<u8>;
    fn expand(&self, msg: &[u8], length: usize) -> Vec<u8>;
}
const MAX_DST_LENGTH: usize = 255;

lazy_static! {
static ref LONG_DST_PREFIX: Vec<u8> = vec![
    //'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-',
    0x48, 0x32, 0x43, 0x2d, 0x4f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x5a, 0x45, 0x2d, 0x44, 0x53, 0x54,
];
}

pub(super) struct ExpanderXof {
    pub(super) id: XofID,
    pub(super) dst: Vec<u8>,
    pub(super) k: Option<usize>,
    pub(super) dst_prime: AtomicRefCell<Option<Vec<u8>>>,
}

impl Expander for ExpanderXof {
    fn construct_dst_prime(&self) -> Vec<u8> {
        let mut dst_prime = if self.dst.len() > MAX_DST_LENGTH {
            let mut hasher = match self.id {
                XofID::SHAKE128 => Shake128::default(),
            };
            hasher.update(&LONG_DST_PREFIX.clone());
            hasher.update(&self.dst);
            hasher
                .finalize_boxed((2 * self.k.unwrap() + 7) >> 3)
                .to_vec()
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
        let lib_str = &[((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8];

        let mut hasher = match self.id {
            XofID::SHAKE128 => Shake128::default(),
        };
        hasher.update(msg);
        hasher.update(lib_str);
        hasher.update(&dst_prime);
        hasher.finalize_boxed(n).to_vec()
    }
}

pub(super) struct ExpanderXmd {
    pub(super) dst: Vec<u8>,
    pub(super) dst_prime: AtomicRefCell<Option<Vec<u8>>>,
    pub(super) id: HashID,
}

impl Expander for ExpanderXmd {
    fn construct_dst_prime(&self) -> Vec<u8> {
        let mut dst_prime = if self.dst.len() > MAX_DST_LENGTH {
            let mut hasher: Box<dyn DynDigest> = match self.id {
                HashID::SHA256 => Box::new(Sha256::new()),
                HashID::SHA512 => Box::new(Sha512::new()),
            };
            hasher.update(&LONG_DST_PREFIX);
            hasher.update(&self.dst);
            (&hasher.finalize()).to_vec()
        } else {
            self.dst.clone()
        };
        dst_prime.push(dst_prime.len() as u8);
        dst_prime
    }
    fn expand(&self, msg: &[u8], n: usize) -> Vec<u8> {
        let (mut hasher, block_size): (Box<dyn DynDigest>, usize) = match self.id {
            HashID::SHA256 => (Box::new(Sha256::new()), 64),
            HashID::SHA512 => (Box::new(Sha512::new()), 128),
        };
        let b_len = hasher.output_size();
        let ell = (n + (b_len - 1)) / b_len;
        if ell > 255 {
            panic!("too big")
        }
        let dst_prime = self
            .dst_prime
            .borrow_mut()
            .get_or_insert(self.construct_dst_prime())
            .clone();
        let z_pad: Vec<u8> = vec![0; block_size];
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

#[cfg(test)]
mod tests;
