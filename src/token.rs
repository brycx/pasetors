use crate::common;
use crate::errors::Error;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;

/// [`UntrustedToken`] can parse PASETO tokens in order to extract individual parts of it.
///
/// A use-case for this would be parsing the tokens footer, if this is not known before receiving it. Then,
/// the footer can be used during verification/decryption of the token itself.
///
/// This type should only be used in order to verify the validity of a token.
///
/// __WARNING__: Anything returned by this type should be treated as **UNTRUSTED** until the token
/// has been verified.
pub struct UntrustedToken {
    header: String,
    message: Vec<u8>,
    footer: Vec<u8>,
}

impl TryFrom<&str> for UntrustedToken {
    type Error = Error;

    /// This fails if `value` is not a PASETO token or it has invalid base64 encoding.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Note: The HEADERs are feature-gated and make a complicated if-statement
        // when used with conditional-compilation. So we used hardcoded here instead.
        if !value.starts_with("v2.public.")
            && !value.starts_with("v2.local.")
            && !value.starts_with("v3.public.")
            && !value.starts_with("v4.public.")
            && !value.starts_with("v4.local.")
        {
            return Err(Error::TokenFormat);
        }

        let parts_split = value.split('.').collect::<Vec<&str>>();
        if parts_split.len() < 3 || parts_split.len() > 4 {
            return Err(Error::TokenFormat);
        }
        let is_footer_present = parts_split.len() == 4;

        Ok(Self {
            header: format!("{}.{}.", parts_split[0], parts_split[1]),
            message: common::decode_b64(parts_split[2])?,
            footer: {
                if is_footer_present {
                    common::decode_b64(parts_split[3])?
                } else {
                    Vec::<u8>::new()
                }
            },
        })
    }
}

impl UntrustedToken {
    /// Return untrusted header of this [`UntrustedToken].
    pub fn get_untrusted_header(&self) -> &str {
        &self.header
    }

    /// Return untrusted message of this [`UntrustedToken].
    pub fn get_untrusted_message(&self) -> &[u8] {
        &self.message
    }

    /// Return untrusted footer of this [`UntrustedToken].
    pub fn get_untrusted_footer(&self) -> &[u8] {
        &self.footer
    }
}
