#[derive(Debug)]
pub enum Errors {
    TokenFormatError,
    Base64DecodingError,
    TokenValidationError,
    KeyError,
    EncryptError,
    DecryptError,
    CsprngError,
}

impl From<base64::DecodeError> for Errors {
    fn from(_: base64::DecodeError) -> Self {
        Errors::Base64DecodingError
    }
}

impl From<rand_core::Error> for Errors {
    fn from(_: rand_core::Error) -> Self {
        Errors::CsprngError
    }
}
