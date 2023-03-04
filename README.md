![Tests](https://github.com/brycx/pasetors/workflows/Tests/badge.svg) [![Documentation](https://docs.rs/pasetors/badge.svg)](https://docs.rs/pasetors/) [![Crates.io](https://img.shields.io/crates/v/pasetors.svg)](https://crates.io/crates/pasetors) [![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/) [![MSRV](https://img.shields.io/badge/MSRV-1.65.0-informational.svg)](https://img.shields.io/badge/MSRV-1.65.0-informational) [![codecov](https://codecov.io/gh/brycx/pasetors/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/pasetors)

### PASETOrs

> "Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the many design deficits that plague the JOSE standards."

PASETO (Platform-Agnostic SEcurity TOkens) are secure stateless tokens. Read more [here](https://github.com/paragonie/paseto) and at [PASETO.io](https://paseto.io/).

This library includes:
- [x] Pure-Rust implementation of the Version 4, 3† and 2 protocol
- [x] PASERK support (limited amount of PASERK-types) with optional `serde` support as well
- [x] `#![no_std]` (with default-features disabled) and `#![forbid(unsafe_code)]`
- [x] WASM-friendly (`wasm32-unknown-unknown` using `#![no_std]`)
- [x] Fuzzing targets
- [x] Test vectors
- [x] Usage examples

† _Only the public variant (`v3.public`) of version 3 is currently supported._

### Usage

[See usage examples here](https://docs.rs/pasetors/).

### Security

This library has **not undergone any third-party security audit**. Usage is at **own risk**. 

### Minimum Supported Rust Version
Rust 1.65.0 or later is supported however, the majority of testing happens with latest stable Rust.

MSRV may be changed at any point and will not be considered a SemVer breaking change.

### Changelog
Please refer to the [CHANGELOG.md](https://github.com/brycx/pasetors/blob/master/CHANGELOG.md) list.

### License
pasetors is licensed under the MIT license. See the `LICENSE` file for more information.