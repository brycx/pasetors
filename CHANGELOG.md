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
