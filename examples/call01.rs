use h2c_rust_ref::{
    GetHashToCurve, EDWARDS25519_XMDSHA256_ELL2_NU_, EDWARDS25519_XMDSHA256_ELL2_RO_,
    EDWARDS25519_XMDSHA512_ELL2_NU_, EDWARDS25519_XMDSHA512_ELL2_RO_,
    EDWARDS448_XOFSHAKE256_ELL2_NU_, EDWARDS448_XOFSHAKE256_ELL2_RO_,
    expander::{Expander2Xof,ExpanderXof},
};
use sha3::{Shake128};
use arrayvec::ArrayVec;
use h2c_rust_ref::expander::Expander2;
use h2c_rust_ref::expander::Expander;
use atomic_refcell::AtomicRefCell;


fn main() {
    let msg = b"This is a message string";
    let dst = b"QUUX-V01-CS02";
    for suite in [
        EDWARDS25519_XMDSHA256_ELL2_NU_,
        EDWARDS25519_XMDSHA256_ELL2_RO_,
        EDWARDS25519_XMDSHA512_ELL2_NU_,
        EDWARDS25519_XMDSHA512_ELL2_RO_,
        EDWARDS448_XOFSHAKE256_ELL2_NU_,
        EDWARDS448_XOFSHAKE256_ELL2_RO_,
    ]
    .iter()
    {
        let dst_prime = ArrayVec::new();
  
        let mut ex = Expander2Xof {
            xofer: Shake128::default(),
            dst_prime:dst_prime,
            k:128,
        };

        let allocations = allocation_counter::count(|| {
            ex.set_dst(dst);
            ex.expand::<10>(msg);
        });
        println!("ex2: {:?} {}", ex, allocations);
 
        let dst_prime = AtomicRefCell::new(None);
  
        let mut ex = ExpanderXof {
            xofer: Shake128::default(),
            k: 128,
            dst:dst.to_vec(),
            dst_prime:dst_prime,
        };

        let allocations = allocation_counter::count(|| {
            ex.construct_dst_prime();
            ex.expand(msg,10);
        });
        println!("ex: {:?} {}", ex, allocations);
 
        let h = suite.get(dst);
        let allocations = allocation_counter::count(|| {
            let mut p = h.hash(msg);
            p.normalize();
        });
        println!("enc: {} {}", suite, allocations);
    }
}
