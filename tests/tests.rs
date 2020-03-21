use std::collections::HashMap;
use std::fs::{read_dir, File};
use std::io::BufReader;

mod json;
use json::SuiteVector;
use libtest_mimic::{run_tests, Arguments, Outcome, Test};

use redox_ecc::ellipticcurve::EllipticCurve;
use redox_ecc::ops::FromFactory;

use h2c_rust_ref::{GetHashToCurve, SUITES_EDWARDS, SUITES_MONTGOMERY, SUITES_WEIERSTRASS};

#[test]
fn vectors() {
    let args = Arguments::from_args();
    let mut tests = Vec::<Test<SuiteVector>>::new();
    for filename in read_dir("./tests/testdata").unwrap() {
        let file = File::open(filename.unwrap().path()).unwrap();
        let u: SuiteVector = serde_json::from_reader(BufReader::new(file)).unwrap();
        tests.push(Test {
            name: u.ciphersuite.clone(),
            data: u,
            kind: String::from(""),
            is_ignored: false,
            is_bench: false,
        })
    }
    run_tests(&args, tests, run_test).exit();
}
fn run_test(Test { data: u, .. }: &Test<SuiteVector>) -> Outcome {
    tt(&SUITES_WEIERSTRASS, u);
    tt(&SUITES_EDWARDS, u);
    tt(&SUITES_MONTGOMERY, u)
}

fn tt<T>(s: &HashMap<String, T>, u: &SuiteVector) -> Outcome
where
    T: GetHashToCurve,
{
    match s.get(&u.ciphersuite) {
        None => Outcome::Ignored,
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
                    return Outcome::Failed {
                        msg: Some(format!(
                            "Suite: {}\ngot:  {}\nwant: {}",
                            u.ciphersuite, got, want
                        )),
                    };
                }
            }
            Outcome::Passed
        }
    }
}
