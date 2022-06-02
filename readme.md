# Hashing to Elliptic Curves

![Rustico](https://github.com/armfazh/h2c-rust-ref/workflows/Rustico/badge.svg)

---

**IETF Data Tracker**: [draft-irtf-cfrg-hash-to-curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve)

**Internet-Draft**: [git repository](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve)

This document specifies a number of algorithms that may be used to encode or hash an arbitrary string to a point on an elliptic curve.

### Reference Implementation

The purpose of this implementation is for generating test vectors and enabling cross compatibility with other implementations.

### Warning

This implementation is **not** protected against any kind of attack,
including side-channel attacks. It **MUST NOT** be used in production systems.

**Limitations**
-   No specific architecture optimizations.
-   No side-channel protection, see [Warning](#Warning) section.

**Development branch** [master](https://github.com/armfazh/h2c-rust-ref/tree/master)

#### Draft versions implemented
 Latest: [v14]

 Previous: [v12], [v08], [v07], [v06], [v05]

 [v14]: https://github.com/armfazh/h2c-rust-ref/tree/v14.0.0
 [v12]: https://github.com/armfazh/h2c-rust-ref/tree/v12.0.0
 [v08]: https://github.com/armfazh/h2c-rust-ref/tree/v8.0.0
 [v07]: https://github.com/armfazh/h2c-rust-ref/tree/v7.0.0
 [v06]: https://github.com/armfazh/h2c-rust-ref/tree/v6.0.0
 [v05]: https://github.com/armfazh/h2c-rust-ref/tree/v5.0.0

#### Compatible Implementations
 -   [Sage](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/master/poc)
 -   [Go](https://github.com/armfazh/h2c-go-ref)

### Internals

![hash to curve](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/main/drawings/diag.png)

### License

BSD 3-Clause License

### Contact

Feel free to open a github issue for anything related to the implementation, otherwise [e-mail](mailto:draft-irtf-cfrg-hash-to-curve@ietf.org) authors of the draft.
