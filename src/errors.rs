#[derive(Debug, PartialEq, Eq)]
/// Errors for token operations.
pub enum Error {
    /// Error for a token with an invalid format.
    TokenFormat,
    /// Error for a failed Base64 (URL-safe without padding) encoding/decoding.
    Base64,
    /// Error for a failed token validation.
    TokenValidation,
    /// Error for an invalid key.
    Key,
    /// Error for a failed encryption operation.
    Encryption,
    /// Error for a failed attempt to generate bytes using a CSPRNG.
    Csprng,
    /// Error for a conversion that would be lossy.
    LossyConversion,
    /// Error for attempting to create a token with an empty payload.
    EmptyPayload,
    /// Error for attempting to create an invalid claim.
    InvalidClaim,
    /// Claim validation error. See [`crate::claims::ClaimsValidationRules::validate_claims`].
    ClaimValidation,
    /// Error for attempting to parse a Claim but found invalid UTF-8 sequence.
    ClaimInvalidUtf8,
    /// Error for attempting to parse a Claim but found invalid JSON sequence.
    ClaimInvalidJson,
    /// Error during (de)serialization of PASERK types.
    PaserkParsing,
    /// Error during signing of a message.
    Signing,
    /// Error during conversion between uncompressed<->compressed public keys.
    PublicKeyConversion,
    /// Error during key generation.
    KeyGeneration,
    /// The payload was not valid UTF-8.
    PayloadInvalidUtf8,
    /// Error during parsing of a `Footer`.
    FooterParsing,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl From<ct_codecs::Error> for Error {
    fn from(_: ct_codecs::Error) -> Self {
        Error::Base64
    }
}

impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Self {
        Error::Csprng
    }
}

impl From<core::num::TryFromIntError> for Error {
    fn from(_: core::num::TryFromIntError) -> Self {
        Error::LossyConversion
    }
}

#[test]
fn test_error_from_impls() {
    let _ = format!("{:?}", Error::TokenFormat);
    let _ = format!("{}", Error::TokenFormat);
    assert_eq!(Error::from(ct_codecs::Error::InvalidInput), Error::Base64);
    assert_eq!(Error::from(getrandom::Error::FAILED_RDRAND), Error::Csprng);
}
