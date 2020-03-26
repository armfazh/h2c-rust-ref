use h2c_rust_ref::{
    GetHashToCurve, EDWARDS25519_XMDSHA256_ELL2_NU_, EDWARDS25519_XMDSHA256_ELL2_RO_,
    EDWARDS25519_XMDSHA512_ELL2_NU_, EDWARDS25519_XMDSHA512_ELL2_RO_,
    EDWARDS448_XMDSHA512_ELL2_NU_, EDWARDS448_XMDSHA512_ELL2_RO_,
};

fn main() {
    let msg = b"This is a message string";
    let dst = b"QUUX-V01-CS02";
    for suite in [
        EDWARDS25519_XMDSHA256_ELL2_NU_,
        EDWARDS25519_XMDSHA256_ELL2_RO_,
        EDWARDS25519_XMDSHA512_ELL2_NU_,
        EDWARDS25519_XMDSHA512_ELL2_RO_,
        EDWARDS448_XMDSHA512_ELL2_NU_,
        EDWARDS448_XMDSHA512_ELL2_RO_,
    ]
    .iter()
    {
        let h = suite.get(dst);
        let mut p = h.hash(msg);
        p.normalize();
        println!("enc: {} {}", suite, p);
    }
}
