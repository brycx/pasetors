![Tests](https://github.com/brycx/pasetors/workflows/Tests/badge.svg) [![Documentation](https://docs.rs/pasetors/badge.svg)](https://docs.rs/pasetors/) [![Crates.io](https://img.shields.io/crates/v/pasetors.svg)](https://crates.io/crates/pasetors) [![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/) [![MSRV](https://img.shields.io/badge/MSRV-1.41-informational.svg)](https://img.shields.io/badge/MSRV-1.41-informational)

### PASETOrs

> "Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the many design deficits that plague the JOSE standards."

PASETO (Platform-Agnostic SEcurity TOkens) are secure stateless tokens. Read more [here](https://github.com/paragonie/paseto) and at [PASETO.io](https://paseto.io/).

This library includes:
- [x] Pure-Rust implementation of the Version 2 protocol
- [x] `#![no_std]` and `#![forbid(unsafe_code)]`
- [x] Fuzzing targets
- [x] Test vectors
- [x] Usage examples

### Usage
```rust
use pasetors::version2::*;
use rand::RngCore;
use ed25519_dalek::Keypair;

let mut csprng = rand::rngs::OsRng{};

// Create and verify a public token
let keypair: Keypair = Keypair::generate(&mut csprng);
let pub_token = PublicToken::sign(&keypair.secret.to_bytes(), &keypair.public.to_bytes(), 
    b"Message to sign", Some(b"footer"))?;
assert!(PublicToken::verify(&keypair.public.to_bytes(), &pub_token, Some(b"footer")).is_ok());

// Create and verify a local token
let mut secret = [0u8; 32];
csprng.try_fill_bytes(&mut secret)?;

let local_token = LocalToken::encrypt(&mut csprng, &secret, b"Message to encrypt and authenticate", Some(b"footer"))?;
assert!(LocalToken::decrypt(&secret, &local_token, Some(b"footer")).is_ok());
```

### Security

This library has **not undergone any third-party security audit**. Usage is at **own risk**. 


The [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) library, used for public tokens, was [included in an audit](https://blog.quarkslab.com/security-audit-of-dalek-libraries.html). The [orion](https://github.com/brycx/orion) library, used for local tokens, has **not** been audited.

### Minimum Supported Rust Version
Rust 1.41 or later is supported however, the majority of testing happens with latest stable Rust.

MSRV may be changed at any point and will not be considered a SemVer breaking change.

### Changelog
Please refer to the [CHANGELOG.md](https://github.com/brycx/pasetors/blob/master/CHANGELOG.md) list.

### License
pasetors is licensed under the MIT license. See the `LICENSE` file for more information.