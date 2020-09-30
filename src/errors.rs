#[derive(Debug)]
pub enum Errors {
    TokenFormatError,
    Base64DecodingError,
    TokenValidationError,
    KeyError,
}

impl From<base64::DecodeError> for Errors {
    fn from(_: base64::DecodeError) -> Self {
        Errors::Base64DecodingError
    }
}
