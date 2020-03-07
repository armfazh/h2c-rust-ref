## h2c_rust_ecc

![Rustico](https://github.com/armfazh/h2c-rust-ref/workflows/Rustico/badge.svg)

The purpose of this library is to provide methods for hashing to curve [[draft-05](https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05)].

### Warning

This implementation is **not** protected against any kind of attack,
including side-channel attacks. Do not use this code for securing any application.

**Limitations**
-   No specify architecture optimizations.
-   No side-channel protection, see [Warning](#Warning) section.

### License

BSD 3-Clause License
