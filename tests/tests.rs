#[test]
fn todo() {
    assert_eq!("0.1.0", "0.1.0");
}

use h2c_rust_ref::{HashToCurve, P256_SHA256_SSWU_NU_};
use redox_ecc::ellipticcurve::EllipticCurve;
use redox_ecc::field::Field;
use redox_ecc::field::FromFactory;
use redox_ecc::instances::{GetCurve, P256};
use redox_ecc::weierstrass::ProyCoordinates;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

mod json;
use json::SuiteVector;

fn readfile<P: AsRef<Path>>(path: P) -> Result<SuiteVector, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let u = serde_json::from_reader(reader)?;
    Ok(u)
}

#[test]
fn one_vector() {
    let namefile = Path::new("./tests/testdata/P256-SHA256-SSWU-NU-.json");
    let u = readfile(namefile).unwrap();
    let h2c = P256_SHA256_SSWU_NU_.get(u.dst.as_bytes());
    let curve = P256.get();
    let f = curve.get_field();
    for v in u.vectors.iter() {
        let got = h2c.hash(v.msg.as_bytes());
        let x = f.from(v.p.x.as_str());
        let y = f.from(v.p.y.as_str());
        let z = f.one();
        let want = curve.new_point(ProyCoordinates { x, y, z });
        // println!("{}", got);
        // println!("{}", want);
        assert_eq!(true, got == want);
    }
}
