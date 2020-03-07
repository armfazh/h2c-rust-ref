use hkdf::Hkdf;
use num_bigint::{BigInt, Sign};
use redox_ecc::field::Field;
use redox_ecc::primefield::Fp;
use sha2::{Sha256, Sha384, Sha512};

use crate::api::{HashID, HashToField};

impl HashToField for Fp {
    type F = Fp;
    fn hash(
        &self,
        h: HashID,
        msg: &[u8],
        dst: &[u8],
        ctr: u8,
        l: usize,
    ) -> <Self::F as Field>::Elt {
        let info: [u8; 5] = [b'H', b'2', b'C', ctr, 1u8];
        let mut vmsg = msg.to_vec();
        vmsg.push(0u8);
        let v = &mut vec![0; l];
        match match h {
            HashID::SHA256 => Hkdf::<Sha256>::new(Some(dst), &vmsg).expand(&info, v),
            HashID::SHA384 => Hkdf::<Sha384>::new(Some(dst), &vmsg).expand(&info, v),
            HashID::SHA512 => Hkdf::<Sha512>::new(Some(dst), &vmsg).expand(&info, v),
        } {
            Ok(_) => self.elt(BigInt::from_bytes_be(Sign::Plus, &v)),
            Err(e) => panic!(e),
        }
    }
}
