use libtest_mimic::{run_tests, Arguments, Outcome, Test};

use std::fs::{read_dir, File};
use std::io::BufReader;

use crate::api::HashID;
use crate::expander::{Expander, ExpanderXmd};

#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct ExpanderVector {
    #[serde(rename = "DST")]
    pub dst: String,
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
        let file = File::open(filename.unwrap().path()).unwrap();
        let u: ExpanderVector = serde_json::from_reader(BufReader::new(file)).unwrap();

        tests.push(Test {
            name: u.name.clone(),
            data: u,
            kind: String::default(),
            is_ignored: false,
            is_bench: false,
        });
    }

    run_tests(&args, tests, do_test).exit_if_failed();
}

fn do_test(Test { data, .. }: &Test<ExpanderVector>) -> Outcome {
    let mut exp: Box<dyn Expander> = match data.hash.as_str() {
        "SHA256" => Box::new(ExpanderXmd {
            dst: Vec::from(data.dst.as_bytes()),
            id: HashID::SHA256,
        }),
        "SHA512" => Box::new(ExpanderXmd {
            dst: Vec::from(data.dst.as_bytes()),
            id: HashID::SHA512,
        }),
        "SHAKE_128" => return Outcome::Ignored,
        _ => unimplemented!(),
    };
    exp.construct_dst_prime();
    for v in data.vectors.iter() {
        let len = usize::from_str_radix(&v.len_in_bytes.trim_start_matches("0x"), 16).unwrap();
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
