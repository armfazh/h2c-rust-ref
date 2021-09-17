use libtest_mimic::{run_tests, Arguments, Outcome, Test};

use std::fs::{read_dir, File};
use std::io::BufReader;

use crate::api::{ExpID, HashID, XofID};
use crate::expander::get_expander;

#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct ExpanderVector {
    #[serde(rename = "DST")]
    pub dst: String,
    pub k: usize,
    pub hash: String,
    pub name: String,
    #[serde(rename = "tests")]
    pub vectors: Vec<TestExpander>,
}

#[derive(Debug, serde_derive::Serialize, serde_derive:: Deserialize)]
pub struct TestExpander {
    #[serde(rename = "DST_prime")]
    pub dst_prime: String,
    pub len_in_bytes: String,
    pub msg: String,
    pub msg_prime: String,
    pub uniform_bytes: String,
}

#[test]
fn expander() {
    let args = Arguments::from_args();
    let mut tests = Vec::<Test<ExpanderVector>>::new();

    for filename in read_dir("./src/expander/testdata").unwrap() {
        let ff = filename.unwrap();
        let file = File::open(ff.path()).unwrap();
        let u: ExpanderVector = serde_json::from_reader(BufReader::new(file)).unwrap();

        tests.push(Test {
            name: ff.file_name().to_str().unwrap().to_string(),
            data: u,
            kind: String::default(),
            is_ignored: false,
            is_bench: false,
        });
    }

    run_tests(&args, tests, do_test).exit_if_failed();
}

fn do_test(Test { data, .. }: &Test<ExpanderVector>) -> Outcome {
    let exp_id = match data.hash.as_str() {
        "SHA256" => ExpID::XMD(HashID::SHA256),
        "SHA384" => ExpID::XMD(HashID::SHA384),
        "SHA512" => ExpID::XMD(HashID::SHA512),
        "SHAKE128" => ExpID::XOF(XofID::SHAKE128),
        "SHAKE256" => ExpID::XOF(XofID::SHAKE256),
        _ => unimplemented!(),
    };
    let exp = get_expander(exp_id, data.dst.as_bytes(), data.k);
    for v in data.vectors.iter() {
        let len = usize::from_str_radix(v.len_in_bytes.trim_start_matches("0x"), 16).unwrap();
        let got = exp.expand(v.msg.as_bytes(), len);
        let want = hex::decode(&v.uniform_bytes).unwrap();
        if got != want {
            return Outcome::Failed {
                msg: Some(format!(
                    "Expander: {}\nVector:   {}\ngot:  {:?}\nwant: {:?}",
                    data.hash, v.msg, got, want,
                )),
            };
        }
    }
    Outcome::Passed
}
