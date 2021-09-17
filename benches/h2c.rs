use criterion::{criterion_group, criterion_main, Criterion};

use h2c_rust_ref::{
    GetHashToCurve, P256_XMDSHA256_SSWU_NU_, P256_XMDSHA256_SSWU_RO_, P384_XMDSHA384_SSWU_NU_,
    P384_XMDSHA384_SSWU_RO_, P521_XMDSHA512_SSWU_NU_, P521_XMDSHA512_SSWU_RO_,
};

fn h2c(c: &mut Criterion) {
    let msg = b"message to be hashed";
    let dst = b"domain separation tag";

    let mut group = c.benchmark_group("Suite");
    group.sample_size(10);

    for suite in [
        P256_XMDSHA256_SSWU_RO_,
        P384_XMDSHA384_SSWU_RO_,
        P521_XMDSHA512_SSWU_RO_,
        P256_XMDSHA256_SSWU_NU_,
        P384_XMDSHA384_SSWU_NU_,
        P521_XMDSHA512_SSWU_NU_,
    ]
    .iter()
    {
        let h = suite.get(dst);
        group.bench_function(format!("{}", suite).as_str(), move |b| {
            b.iter(|| h.hash(msg))
        });
    }
    group.finish()
}

criterion_group!(h2c_bench, h2c);
criterion_main!(h2c_bench);
