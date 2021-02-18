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
fn suites() {
    let args = Arguments::from_args();
    let mut tests_weierstrass = Vec::<Test<SuiteVector>>::new();
    let mut tests_montgomery = Vec::<Test<SuiteVector>>::new();
    let mut tests_edwards = Vec::<Test<SuiteVector>>::new();
    let mut tests_ignored = Vec::<Test<SuiteVector>>::new();

    for filename in read_dir("./tests/testdata").unwrap() {
        let file = File::open(filename.unwrap().path()).unwrap();
        let u: SuiteVector = serde_json::from_reader(BufReader::new(file)).unwrap();
        let key = u.ciphersuite.clone();
        let mut test = Test {
            name: u.ciphersuite.clone(),
            data: u,
            kind: String::default(),
            is_ignored: false,
            is_bench: false,
        };
        if SUITES_WEIERSTRASS.contains_key(&key) {
            test.is_ignored = false;
            tests_weierstrass.push(test);
        } else if SUITES_MONTGOMERY.contains_key(&key) {
            test.is_ignored = false;
            tests_montgomery.push(test);
        } else if SUITES_EDWARDS.contains_key(&key) {
            test.is_ignored = false;
            tests_edwards.push(test);
        } else {
            test.is_ignored = true;
            tests_ignored.push(test);
        }
    }
    run_tests(&args, tests_weierstrass, run_test_w).exit_if_failed();
    run_tests(&args, tests_edwards, run_test_e).exit_if_failed();
    run_tests(&args, tests_montgomery, run_test_m).exit_if_failed();
    run_tests(&args, tests_ignored, run_test_w).exit_if_failed();
}

fn run_test_w(Test { data, .. }: &Test<SuiteVector>) -> Outcome {
    tt(&SUITES_WEIERSTRASS, data)
}
fn run_test_e(Test { data, .. }: &Test<SuiteVector>) -> Outcome {
    tt(&SUITES_EDWARDS, data)
}
fn run_test_m(Test { data, .. }: &Test<SuiteVector>) -> Outcome {
    tt(&SUITES_MONTGOMERY, data)
}

fn tt<T>(s: &HashMap<String, T>, u: &SuiteVector) -> Outcome
where
    T: GetHashToCurve,
    for<'a> <<T as GetHashToCurve>::E as EllipticCurve>::F: FromFactory<&'a str>,
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
