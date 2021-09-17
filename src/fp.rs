use redox_ecc::field::Field;
use redox_ecc::ops::Deserialize;
use redox_ecc::primefield::{Fp, FpElt};

use crate::api::HashToField;
use crate::expander::Expander;

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
            match self.f.from_bytes_be(t) {
                Ok(v) => u.push(v),
                Err(e) => panic!("{}", e),
            }
        }
        u
    }
}
