#[derive(Debug, PartialEq)]
/// Errors for token operations.
pub enum Errors {
    /// Error for a token with an invalid format.
    TokenFormatError,
    /// Error for a failed Base64 (URL-safe without padding) decoding.
    Base64DecodingError,
    /// Error for a failed token validation.
    TokenValidationError,
    /// Error for an invalid key.
    KeyError,
    /// Error for a failed encryption operation.
    EncryptError,
    /// Error for a failed attempt to generate bytes using a CSPRNG.
    CsprngError,
    /// Error for a conversion that would be lossy.
    LossyConversionError,
    /// Error for attempting to create a token with an empty payload.
    EmptyPayloadError,
    /// Error for attempting to create an invalid claim.
    InvalidClaimError,
    /// Claim validation error. Either, a claim was expected but not present,
    /// the expected claim did not match the actual, the token is not valid yet, has
    /// expired or DateTime parsing has failed.
    ClaimValidationError,
    /// Error for attempting to parse a Claim but found invalid UTF-8 sequence.
    ClaimInvalidUtf8,
    /// Error for attempting to parse a Claim but found invalid JSON sequence.
    ClaimInvalidJson,
}

impl From<ct_codecs::Error> for Errors {
    fn from(_: ct_codecs::Error) -> Self {
        Errors::Base64DecodingError
    }
}

impl From<getrandom::Error> for Errors {
    fn from(_: getrandom::Error) -> Self {
        Errors::CsprngError
    }
}

impl From<core::num::TryFromIntError> for Errors {
    fn from(_: core::num::TryFromIntError) -> Self {
        Errors::LossyConversionError
    }
}
