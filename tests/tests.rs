use std::collections::HashMap;
use std::fs::{read_dir, File};
use std::io::BufReader;

mod json;
use json::SuiteVector;
use libtest_mimic::{run, Arguments, Failed, Trial};
use redox_ecc::ellipticcurve::EllipticCurve;
use redox_ecc::ops::FromFactory;

use h2c_rust_ref::{GetHashToCurve, SUITES_EDWARDS, SUITES_MONTGOMERY, SUITES_WEIERSTRASS};

#[test]
fn suites() {
    let args = Arguments::from_args();
    let mut tests_weierstrass = Vec::<Trial>::new();
    let mut tests_montgomery = Vec::<Trial>::new();
    let mut tests_edwards = Vec::<Trial>::new();
    let mut tests_ignored = Vec::<Trial>::new();

    for filename in read_dir("./tests/testdata").unwrap() {
        let file = File::open(filename.unwrap().path()).unwrap();
        let u: SuiteVector = serde_json::from_reader(BufReader::new(file)).unwrap();
        let key = u.ciphersuite.clone();
        let name = u.ciphersuite.clone();
        if SUITES_WEIERSTRASS.contains_key(&key) {
            tests_weierstrass.push(Trial::test(name, move || tt(&SUITES_WEIERSTRASS, &u)));
        } else if SUITES_MONTGOMERY.contains_key(&key) {
            tests_montgomery.push(Trial::test(name, move || tt(&SUITES_MONTGOMERY, &u)));
        } else if SUITES_EDWARDS.contains_key(&key) {
            tests_edwards.push(Trial::test(name, move || tt(&SUITES_EDWARDS, &u)));
        } else {
            tests_ignored
                .push(Trial::test(name, move || Err("ignored".into())).with_ignored_flag(true));
        }
    }

    run(&args, tests_weierstrass).exit_if_failed();
    run(&args, tests_edwards).exit_if_failed();
    run(&args, tests_montgomery).exit_if_failed();
    run(&args, tests_ignored).exit_if_failed();
}

fn tt<T>(s: &HashMap<String, T>, u: &SuiteVector) -> Result<(), Failed>
where
    T: GetHashToCurve,
    for<'a> <<T as GetHashToCurve>::E as EllipticCurve>::F: FromFactory<&'a str>,
{
    match s.get(&u.ciphersuite) {
        None => Err("suite not found".into()),
        Some(suite) => {
            let h2c = suite.get(u.dst.as_bytes());
            let curve = h2c.get_curve();
            let f = curve.get_field();
            for v in u.vectors.iter() {
                let got = h2c.hash(v.msg.as_bytes());
                let x = f.from(&v.p.x);
                let y = f.from(&v.p.y);
                let want = curve.new_point(x, y);
                if got != want {
                    return Err(
                        format!("Suite: {}\ngot:  {}\nwant: {}", u.ciphersuite, got, want).into(),
                    );
                }
            }
            Ok(())
        }
    }
}
