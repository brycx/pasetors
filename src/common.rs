use crate::errors::Error;
use crate::token::private::Purpose;
use crate::token::UntrustedToken;
use crate::version::private::Version;
use alloc::string::String;
use alloc::vec::Vec;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use subtle::ConstantTimeEq;

/// Encode bytes with Base64 URL-safe and no padding.
pub(crate) fn encode_b64<T: AsRef<[u8]>>(bytes: T) -> Result<String, Error> {
    let inlen = bytes.as_ref().len();
    let mut buf = vec![0u8; Base64UrlSafeNoPadding::encoded_len(inlen)?];

    let ret: String = Base64UrlSafeNoPadding::encode_to_str(&mut buf, bytes)?.into();

    Ok(ret)
}

/// Decode string with Base64 URL-safe and no padding.
pub(crate) fn decode_b64<T: AsRef<[u8]>>(encoded: T) -> Result<Vec<u8>, Error> {
    let inlen = encoded.as_ref().len();
    // We can use encoded len here, even if it returns more than needed,
    // because ct-codecs allows this.
    let mut buf = vec![0u8; Base64UrlSafeNoPadding::encoded_len(inlen)?];

    let ret: Vec<u8> = Base64UrlSafeNoPadding::decode(&mut buf, encoded, None)?.into();

    Ok(ret)
}

/// If a footer is present, this is validated against the supplied.
pub(crate) fn validate_footer_untrusted_token<T: Purpose<V>, V: Version>(
    token: &UntrustedToken<T, V>,
    footer: Option<&[u8]>,
) -> Result<(), Error> {
    // A known footer was supplied for comparison.
    if let Some(known_footer) = footer {
        if token.untrusted_footer().is_empty() {
            // If one was supplied, one must exist in the untrusted.
            return Err(Error::TokenValidation);
        }

        if !bool::from(known_footer.ct_eq(token.untrusted_footer())) {
            return Err(Error::TokenValidation);
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct TestFile {
        pub(crate) name: String,
        pub(crate) tests: Vec<PasetoTest>,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct PasetoTest {
        pub(crate) name: String,
        #[serde(rename(deserialize = "expect-fail"))]
        pub(crate) expect_fail: bool,
        pub(crate) key: Option<String>,
        pub(crate) nonce: Option<String>,
        #[serde(rename(deserialize = "public-key"))]
        pub(crate) public_key: Option<String>,
        #[serde(rename(deserialize = "secret-key"))]
        pub(crate) secret_key: Option<String>,
        #[serde(rename(deserialize = "secret-key-seed"))]
        pub(crate) secret_key_seed: Option<String>,
        #[serde(rename(deserialize = "public-key-pem"))]
        pub(crate) public_key_pem: Option<String>,
        #[serde(rename(deserialize = "secret-key-pem"))]
        pub(crate) secret_key_pem: Option<String>,
        pub(crate) token: String,
        pub(crate) payload: Option<Value>,
        pub(crate) footer: String,
        #[serde(rename(deserialize = "implicit-assertion"))]
        pub(crate) implicit_assertion: String,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct Payload {
        pub(crate) data: String,
        pub(crate) exp: String,
    }
}
