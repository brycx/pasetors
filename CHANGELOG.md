### 0.5.0 (pre-release)

__Date:__ TBD

__Changelog:__
- Bump MSRV to `1.56.0`
- Implement `v3.public` tokens ([#40](https://github.com/brycx/pasetors/issues/40))
- Introduce separate crate-features for each version and one for PASERK: `v2`, `v3`, `v4` and `paserk`. `std`, `v4` and `paserk` are enabled by default
- Add support for the PASERK [ID operation](https://github.com/paseto-standard/paserk/blob/master/operations/ID.md) ([#40](https://github.com/brycx/pasetors/issues/40))
- Stricter permissions for GH Actions workflows ([#43](https://github.com/brycx/pasetors/pull/43))
- Add `Generate` trait and implement this for all key-types, removing also `SymmetricKey::gen()` ([#45](https://github.com/brycx/pasetors/issues/45))

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
