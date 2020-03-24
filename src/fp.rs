use digest::DynDigest;
use sha2::{Digest, Sha256, Sha512};

use redox_ecc::field::Field;
use redox_ecc::ops::Deserialize;
use redox_ecc::primefield::{Fp, FpElt};

use crate::api::{HashID, HashToField};

pub trait Expander {
    fn shorten_dst(&mut self);
    fn expand(&self, msg: &[u8], length: usize) -> Vec<u8>;
}
const MAX_DST_LENGTH: usize = 255;
pub(super) struct ExpanderXmd {
    pub(super) dst: Vec<u8>,
    pub(super) id: HashID,
}

lazy_static! {
static ref LONG_DST_PREFIX: Vec<u8> = vec![
    //'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-',
    0x48, 0x32, 0x43, 0x2d, 0x4f, 0x56, 0x45, 0x52, 0x53, 0x49, 0x5a, 0x45, 0x2d, 0x44, 0x53, 0x54,
];
}

impl Expander for ExpanderXmd {
    fn shorten_dst(&mut self) {
        if self.dst.len() > MAX_DST_LENGTH {
            let mut hasher: Box<dyn DynDigest> = match self.id {
                HashID::SHA256 => Box::new(Sha256::new()),
                HashID::SHA512 => Box::new(Sha512::new()),
            };
            hasher.input(&LONG_DST_PREFIX);
            hasher.input(&self.dst);
            self.dst = (&hasher.result()).to_vec();
        }
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
        let mut dst_prime = vec![self.dst.len() as u8];
        dst_prime.extend_from_slice(&self.dst);
        let z_pad: Vec<u8> = vec![0; block_size];
        let lib_str = &[((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8];

        hasher.reset();
        hasher.input(&z_pad);
        hasher.input(msg);
        hasher.input(lib_str);
        hasher.input(&vec![0]);
        hasher.input(&dst_prime);
        let b0 = hasher.result_reset();

        hasher.reset();
        hasher.input(&b0);
        hasher.input(&vec![1]);
        hasher.input(&dst_prime);
        let mut bi = hasher.result_reset();

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&bi);
        for i in 2..(ell + 1) {
            hasher.reset();
            hasher.input(&xor(&bi, &b0));
            hasher.input(&vec![i as u8]);
            hasher.input(&dst_prime);
            bi = hasher.result_reset();
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

pub(super) struct FpHasher {
    pub(super) f: Fp,
    pub(super) l: usize,
    pub(super) exp: Box<dyn Expander>,
}

impl HashToField for FpHasher {
    type F = Fp;
    fn hash(&self, msg: &[u8], count: usize) -> Vec<<Self::F as Field>::Elt> {
        const M: usize = 1;
        let length = count * M * self.l;

        let pseudo = self.exp.expand(msg, length);
        let mut u = Vec::<FpElt>::with_capacity(count);
        for i in 0..count {
            let offset: usize = self.l * (i * M);
            let t = &pseudo[offset..(offset + self.l)];
            match self.f.from_bytes_be(&t) {
                Ok(v) => u.push(v),
                Err(e) => panic!(e),
            }
        }
        u
    }
}
