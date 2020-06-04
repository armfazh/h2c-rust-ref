use digest::DynDigest;
use sha2::{Digest, Sha256, Sha512};

use crate::api::HashID;

pub trait Expander {
    fn construct_dst_prime(&mut self);
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
    fn construct_dst_prime(&mut self) {
        if self.dst.len() > MAX_DST_LENGTH {
            let mut hasher: Box<dyn DynDigest> = match self.id {
                HashID::SHA256 => Box::new(Sha256::new()),
                HashID::SHA512 => Box::new(Sha512::new()),
            };
            hasher.input(&LONG_DST_PREFIX);
            hasher.input(&self.dst);
            self.dst = (&hasher.result()).to_vec();
        }
        self.dst.push(self.dst.len() as u8)
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
        let z_pad: Vec<u8> = vec![0; block_size];
        let lib_str = &[((n >> 8) & 0xFF) as u8, (n & 0xFF) as u8];

        hasher.reset();
        hasher.input(&z_pad);
        hasher.input(msg);
        hasher.input(lib_str);
        hasher.input(&[0u8]);
        hasher.input(&self.dst);
        let b0 = hasher.result_reset();

        hasher.reset();
        hasher.input(&b0);
        hasher.input(&[1u8]);
        hasher.input(&self.dst);
        let mut bi = hasher.result_reset();

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&bi);
        for i in 2..(ell + 1) {
            hasher.reset();
            hasher.input(&xor(&bi, &b0));
            hasher.input(&[i as u8]);
            hasher.input(&self.dst);
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

#[cfg(test)]
mod tests;
