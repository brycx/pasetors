### 0.6.7

__Date:__ June 10, 2023.

__Changelog:__
- Add security policy.
- Add `Claims::new_expires_in()` ([#96](https://github.com/brycx/pasetors/issues/96)).


### 0.6.6

__Date:__ March 4, 2023.

__Changelog:__
- Update license year to 2023.
- Bump `p384` to `0.13.0`
- Bump MSRV to `1.65.0`
- Switch from `actions-rs/tarpaulin` to `cargo-tarpaulin` in CI.


### 0.6.5

__Date:__ December 14, 2022.

__Changelog:__
- `SymmetricKey`, `AsymmetricSecretKey` and `AsymmetricKeyPair` now implement `Clone`.

### 0.6.4

__Date:__ November 17, 2022.

__Changelog:__
- `AsymmetricSecretKey` now re-computes the public key from the secret seed to check if they match. If they don't an error is returned. Because we use `ed25519-compact` crate for Ed25519, if an all-zero seed is used, the creation of `AsymmetricSecretKey` will panic.

### 0.6.3

__Date:__ October 15, 2022.

__Changelog:__
- Add optional `serde` support for keys + PASERK ID, to be de/serialized from/to PASERK strings. Also introducing a new optional feature `serde` (see [#26](https://github.com/brycx/pasetors/issues/26), by [@SanchithHegde](https://github.com/SanchithHegde))
- Clippy improvements to tests (see [#69](https://github.com/brycx/pasetors/pull/69), by [@SanchithHegde](https://github.com/SanchithHegde))
- Update `ed25519-compact` to `2.0.2` (see [#72](https://github.com/brycx/pasetors/pull/72))

### 0.6.2

__Date:__ September 23, 2022.

__Changelog:__
- Fix `ed25519-compact` imports that broke build after the crate bumped to `1.0.13+`

### 0.6.1

__Date:__ September 20, 2022.

__Changelog:__
- Bump MSRV to `1.59.0`
- `clippy` fixes
- Add `rust-version` field to `Cargo.toml`
- Update copyright year to 2022


### 0.6.0

__Date:__ June 20, 2022.

__Changelog:__
- PASERK operations are now implemented for `AsymmetricSecretKey<V2>` and `AsymmetricSecretKey<V4>` instead of `AsymmetricKeyPair<V2>` and `AsymmetricKeyPair<V4>`, respectively
- All `sign()` operations with public tokens now take only the secret key
- `V2` and `V4` token's `AsymmetricSecretKey<>` are now defined to contain both the Ed25519 secret seed and the public key (see https://github.com/MystenLabs/ed25519-unsafe-libs)
- `TryFrom<AsymmetricSecretKey<>> for AsymmetricPublicKey<>` is now provided for `V2` and `V4` as well


### 0.5.0

__Date:__ June 4, 2022.

__Changelog:__
- Bump MSRV to `1.57.0`
- Implement `v3.public` tokens ([#40](https://github.com/brycx/pasetors/issues/40))
- Introduce separate crate-features for each version and one for PASERK: `v2`, `v3`, `v4` and `paserk`. `std`, `v4` and `paserk` are enabled by default
- Add support for the PASERK [ID operation](https://github.com/paseto-standard/paserk/blob/master/operations/ID.md) ([#40](https://github.com/brycx/pasetors/issues/40))
- Stricter permissions for GH Actions workflows ([#43](https://github.com/brycx/pasetors/pull/43))
- Add `Generate` trait and implement this for all key-types, removing also `SymmetricKey::gen()` ([#45](https://github.com/brycx/pasetors/issues/45))
- Switch from `ed25519-dalek` to `ed25519-compact` ([#48](https://github.com/brycx/pasetors/issues/48))
- Add new types `token::UntrustedToken` and `token::TrustedToken` which are now used by `verify()`/`decrypt()` operations. 
These allow extracting parts of tokens before and after verification ([#47](https://github.com/brycx/pasetors/issues/47)) 
- Version structs previously available in `keys::` have been moved to a new `version::` module
- Add `Footer` type that makes it easier to create JSON-encoded footers ([#52](https://github.com/brycx/pasetors/pull/52))
- PASERK deserialization of keys now takes `&str` instead of `String` ([#53](https://github.com/brycx/pasetors/issues/53))
- Rename `Error::Base64Decoding` -> `Error::Base64`

### 0.4.2

__Date:__ November 27, 2021.

__Changelog:__
- Update Orion to `0.17` ([#39](https://github.com/brycx/pasetors/pull/39))
- Bump MSRV to `1.52`

### 0.4.1

__Date:__ November 11, 2021.

__Changelog:__
- Enable `getrandom/js` feature and test `wasm32-unknown-unknown` in CI ([#37](https://github.com/brycx/pasetors/pull/37))

### 0.4.0

__Date:__ October 25, 2021.

__Changelog:__
- [Security fix]: Switched from `chrono` to `time` crate ([#30](https://github.com/brycx/pasetors/pull/30))
- `Error` now implements `std::error::Error` ([#27](https://github.com/brycx/pasetors/pull/27)) (by [@not-my-profile](https://github.com/not-my-profile))
- `Errors` enum has be renamed to `Error` and "error" postfixes have been trimmed from variants ([#33](https://github.com/brycx/pasetors/pull/33))
- `SymmetricKey`, `AsymmetricPublicKey` and `AsymmetricSecretKey` have been made generic over their versions ([#31](https://github.com/brycx/pasetors/pull/31)) (by [@not-my-profile](https://github.com/not-my-profile))
- Add support for `local`, `public` and `secret` PASERK types for keys ([#24](https://github.com/brycx/pasetors/pull/24))

### 0.3.0

__Date:__ September 22, 2021.

__Changelog:__
- Implement version 4 of the PASETO specification
- New `SymmetricKey`, `AsymmetricPublicKey` and `AsymmetricSecretKey` now used throughout the API of both version 2 and 4 ([#14](https://github.com/brycx/pasetors/issues/14))
- Use new test vectors from https://github.com/paseto-standard/test-vectors
- Empty payloads are no longer allowed (see https://github.com/paseto-standard/paseto-spec/issues/17) and `Errors::EmptyPayloadError` has been added
- New `Claims` type to easily define claims for tokens and `ClaimsValidationRules` to validate such claims.
- New `std` feature which is enabled by default. This means, that to be `no_std`, `pasetors` has to be declared without default features.
- New `local`/`public` API which uses the latest version, and automatically handles validation of `Claims`.

### 0.2.0

__Date:__ June 2, 2021.

__Changelog:__
- Remove `Csprng` trait from public API and use `getrandom` instead
- Update Orion to `0.16`


### 0.1.1 

__Date:__ March 21, 2021.

__Changelog:__
- Switch from `base64` to `ct-codecs` to provide constant-time Base64 encoding/decoding


### 0.1.0 - Initial release

__Date:__ October 12, 2020.
