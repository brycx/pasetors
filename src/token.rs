use crate::alloc::string::ToString;
#[cfg(feature = "std")]
use crate::claims::Claims;
use crate::common;
use crate::errors::Error;
#[cfg(feature = "std")]
use crate::footer::Footer;
use crate::token::private::Purpose;
use crate::version::private::Version;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::marker::PhantomData;

pub(crate) mod private {
    use super::Error;
    use crate::version::private::Version;

    // Inside private module to prevent users from implementing this themself.

    /// Purpose (`local`/`public`) of a token, given a version `V`.
    pub trait Purpose<V: Version> {
        /// Validate the header for a given version and purpose for some token.
        fn validate_header(token: &str) -> Result<(), Error>;
        /// Validate the tokens raw (decoded base64)
        /// message length for a given version and purpose for some token.
        fn validate_token_message_len(message: &[u8]) -> Result<(), Error>;
        /// Parse the raw payload of a token. Either the ciphertext or the message that was signed.
        /// The length **MUST** have been verified beforehand.
        fn parse_raw_payload(message: &[u8]) -> &[u8];
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// A public token.
pub struct Public;

#[derive(Debug, PartialEq, Eq, Clone)]
/// A local token.
pub struct Local;

impl<V: Version> Purpose<V> for Public {
    fn validate_header(token: &str) -> Result<(), Error> {
        if token.is_empty() || !token.starts_with(V::PUBLIC_HEADER) {
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn validate_token_message_len(message: &[u8]) -> Result<(), Error> {
        if message.len() <= V::PUBLIC_SIG {
            // Empty payload encrypted. Disallowed by PASETO
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn parse_raw_payload(message: &[u8]) -> &[u8] {
        debug_assert!(message.len() > V::PUBLIC_SIG);
        &message[..message.len() - V::PUBLIC_SIG]
    }
}

impl<V: Version> Purpose<V> for Local {
    fn validate_header(token: &str) -> Result<(), Error> {
        if token.is_empty() || !token.starts_with(V::LOCAL_HEADER) {
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn validate_token_message_len(message: &[u8]) -> Result<(), Error> {
        if message.len() <= V::LOCAL_NONCE + V::LOCAL_TAG {
            // Empty payload encrypted. Disallowed by PASETO
            return Err(Error::TokenFormat);
        }

        Ok(())
    }

    fn parse_raw_payload(message: &[u8]) -> &[u8] {
        debug_assert!(message.len() > V::LOCAL_TAG + V::LOCAL_NONCE);
        &message[V::LOCAL_NONCE..message.len() - V::LOCAL_TAG]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A [`TrustedToken`] is returned by either a `verify()` or `decrypt()` operation and represents
/// a validated token.
///
/// It represents a authenticated and non-tampered token. It **does not** validate additional things,
/// such as claims that may be within the token payload itself. These must still be validated separately.
///
/// However, using the [`crate::public`] and [`crate::local`] API will automatically handle claims
/// validation. Any validated claims may be retrieved with [`TrustedToken::payload_claims()`].
pub struct TrustedToken {
    header: String,
    // PASETO requires the payload to be valid JSON in UTF-8, so we say String for UTF-8.
    payload: String,
    #[cfg(feature = "std")]
    // If std is available, we also keep claims as JSON.
    payload_claims: Option<Claims>,
    footer: Vec<u8>,
    implicit_assert: Vec<u8>,
}

impl TrustedToken {
    pub(crate) fn _new(
        header: &str,
        payload: &[u8],
        footer: &[u8],
        implicit_assert: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            header: header.to_string(),
            payload: String::from_utf8(payload.to_vec()).map_err(|_| Error::PayloadInvalidUtf8)?,
            #[cfg(feature = "std")]
            payload_claims: None,
            footer: footer.to_vec(),
            implicit_assert: implicit_assert.to_vec(),
        })
    }

    /// Get the header that is used for this token.
    pub fn header(&self) -> &str {
        &self.header
    }

    /// Get the payload that is used for this token.
    pub fn payload(&self) -> &str {
        &self.payload
    }

    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    /// Return the optional and validated [`Claims`] parsed from the tokens payload.
    ///
    /// - `None`: If no [`Claims`] have been parsed or validated.
    /// - `Some`: If some [`Claims`] have been parsed **AND** validated.
    ///
    /// [`Claims`]: crate::claims::Claims
    pub fn payload_claims(&self) -> Option<&Claims> {
        debug_assert!(self.payload_claims.is_some());
        match &self.payload_claims {
            Some(claims) => Some(claims),
            None => None,
        }
    }

    #[cfg(feature = "std")]
    /// Set the payload claims **AFTER HAVING VALIDATED THEM**.
    pub(crate) fn set_payload_claims(&mut self, claims: Claims) {
        self.payload_claims = Some(claims);
    }

    /// Get the footer used to create the token.
    ///
    /// Empty if `None` was used during creation.
    pub fn footer(&self) -> &[u8] {
        &self.footer
    }

    /// Get the implicit assertion used to create the token.
    ///
    /// Empty if `None` was used during creation.
    /// If token was created using `V2`, then it will always be empty.
    pub fn implicit_assert(&self) -> &[u8] {
        &self.implicit_assert
    }
}

#[cfg(feature = "std")]
impl TryFrom<&TrustedToken> for Footer {
    type Error = Error;

    fn try_from(value: &TrustedToken) -> Result<Self, Self::Error> {
        if value.footer.is_empty() {
            return Err(Error::FooterParsing);
        }

        let mut footer = Footer::new();
        footer.parse_bytes(value.footer())?;

        Ok(footer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// [`UntrustedToken`] can parse PASETO tokens in order to extract individual parts of it.
///
/// A use-case for this would be parsing the tokens footer, if this is not known before receiving it. Then,
/// the footer can be used during verification/decryption of the token itself.
///
/// This type should only be used in order to verify the validity of a token.
///
/// __WARNING__: Anything returned by this type should be treated as **UNTRUSTED** until the token
/// has been verified.
pub struct UntrustedToken<T, V> {
    message: Vec<u8>,
    footer: Vec<u8>,
    phantom_t: PhantomData<T>,
    phantom_v: PhantomData<V>,
}

impl<T: Purpose<V>, V: Version> TryFrom<&str> for UntrustedToken<T, V> {
    type Error = Error;

    /// This fails if `value` is not a PASETO token or it has invalid base64 encoding.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        T::validate_header(value)?;

        let parts_split = value.split('.').collect::<Vec<&str>>();
        if parts_split.len() < 3 || parts_split.len() > 4 {
            return Err(Error::TokenFormat);
        }
        if parts_split[2].is_empty() {
            // Empty payload entirely
            return Err(Error::TokenFormat);
        }

        let m_raw = common::decode_b64(parts_split[2])?;
        T::validate_token_message_len(&m_raw)?;
        let is_footer_present = parts_split.len() == 4;

        Ok(Self {
            message: m_raw,
            footer: {
                if is_footer_present {
                    common::decode_b64(parts_split[3])?
                } else {
                    Vec::<u8>::new()
                }
            },
            phantom_t: PhantomData,
            phantom_v: PhantomData,
        })
    }
}

impl<T: Purpose<V>, V: Version> TryFrom<&String> for UntrustedToken<T, V> {
    type Error = Error;

    /// This fails if `value` is not a PASETO token or it has invalid base64 encoding.
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<T: Purpose<V>, V: Version> UntrustedToken<T, V> {
    /// Return untrusted message of this [`UntrustedToken`].
    /// If it is a [`Local`] token, this is the encrypted message with nonce and tag.
    /// If it is a [`Public`] token, the signature is included.
    pub fn untrusted_message(&self) -> &[u8] {
        &self.message
    }

    /// Return untrusted payload only of this [`UntrustedToken`]'s message body.
    /// If it is a [`Local`] token, this is the encrypted message sans nonce and tag.
    /// If it is a [`Public`] token, the signature is not included.
    pub fn untrusted_payload(&self) -> &[u8] {
        T::parse_raw_payload(self.untrusted_message())
    }

    /// Return untrusted footer of this [`UntrustedToken`].
    /// Empty if there was no footer in the token.
    pub fn untrusted_footer(&self) -> &[u8] {
        &self.footer
    }
}

#[cfg(test)]
#[cfg(all(feature = "v2", feature = "v3", feature = "v4"))]
mod tests_untrusted {
    use super::*;
    use crate::common::encode_b64;
    use crate::errors::Error;
    use crate::version::private::Version;
    use crate::{version2::V2, version3::V3, version4::V4};

    const V2_PUBLIC_TOKEN: &str = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const V2_LOCAL_TOKEN: &str = "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const V3_PUBLIC_TOKEN: &str = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9";
    const V4_PUBLIC_TOKEN: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const V4_LOCAL_TOKEN: &str = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    const TOKEN_LIST: [&str; 5] = [
        V2_PUBLIC_TOKEN,
        V2_LOCAL_TOKEN,
        V3_PUBLIC_TOKEN,
        V4_LOCAL_TOKEN,
        V4_PUBLIC_TOKEN,
    ];

    fn test_untrusted_parse_fails(invalid: &str, expected_err: Error) {
        if invalid.starts_with(V2::LOCAL_HEADER) {
            assert_eq!(
                UntrustedToken::<Local, V2>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V2::PUBLIC_HEADER) {
            assert_eq!(
                UntrustedToken::<Public, V2>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V3::LOCAL_HEADER) {
            assert_eq!(
                UntrustedToken::<Local, V3>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V3::PUBLIC_HEADER) {
            assert_eq!(
                UntrustedToken::<Public, V3>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V4::LOCAL_HEADER) {
            assert_eq!(
                UntrustedToken::<Local, V4>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
        if invalid.starts_with(V4::PUBLIC_HEADER) {
            assert_eq!(
                UntrustedToken::<Public, V4>::try_from(invalid).unwrap_err(),
                expected_err
            );
        }
    }

    #[test]
    fn empty_string() {
        assert_eq!(
            UntrustedToken::<Local, V2>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V2>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V3>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V3>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V4>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V4>::try_from("").unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    fn no_separators() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();
            let invalid: String = split.iter().copied().collect();

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    // NOTE: See https://github.com/paseto-standard/paseto-spec/issues/17
    fn missing_payload() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();
            let invalid: String = format!("{}.{}..{}", split[0], split[1], split[3]);

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    fn payload_too_short() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();
            let invalid: String = format!(
                "{}.{}.{}.{}",
                split[0],
                split[1],
                encode_b64(split[0].as_bytes()).unwrap(),
                split[3]
            );

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    fn extra_after_footer() {
        for token in TOKEN_LIST {
            let mut invalid = token.to_string();
            invalid.push_str(".shouldNotBeHere");

            test_untrusted_parse_fails(&invalid, Error::TokenFormat);
        }
    }

    #[test]
    fn invalid_header() {
        // Invalid version
        assert_eq!(
            UntrustedToken::<Public, V2>::try_from(&V2_PUBLIC_TOKEN.replace("v2", "v4"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V2>::try_from(&V2_LOCAL_TOKEN.replace("v2", "v4")).unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V3>::try_from(&V3_PUBLIC_TOKEN.replace("v3", "v2"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V4>::try_from(&V4_LOCAL_TOKEN.replace("v4", "v2")).unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V4>::try_from(&V4_PUBLIC_TOKEN.replace("v4", "v2"))
                .unwrap_err(),
            Error::TokenFormat
        );

        // Invalid purpose
        assert_eq!(
            UntrustedToken::<Public, V2>::try_from(&V2_PUBLIC_TOKEN.replace("public", "local"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V2>::try_from(&V2_LOCAL_TOKEN.replace("local", "public"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V3>::try_from(&V3_PUBLIC_TOKEN.replace("public", "local"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Local, V4>::try_from(&V4_LOCAL_TOKEN.replace("local", "public"))
                .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            UntrustedToken::<Public, V4>::try_from(&V4_PUBLIC_TOKEN.replace("public", "local"))
                .unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    fn invalid_base64() {
        for token in TOKEN_LIST {
            let split = token.split('.').collect::<Vec<&str>>();

            let invalid: String = format!("{}.{}.{}!.{}", split[0], split[1], split[2], split[3]);
            test_untrusted_parse_fails(&invalid, Error::Base64);

            let invalid: String = format!("{}.{}.{}.{}!", split[0], split[1], split[2], split[3]);
            test_untrusted_parse_fails(&invalid, Error::Base64);
        }
    }

    #[cfg(feature = "v2")]
    #[test]
    fn valid_v2_local() {
        // "2-E-1"
        let valid_no_footer = "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ";
        // "2-E-5"
        let valid_with_footer = "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Local, V2>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Local, V2>::try_from(valid_with_footer).unwrap();

        // Note: We don't test for untrusted message, since it is encrypted.
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[cfg(feature = "v2")]
    #[test]
    fn valid_v2_public() {
        // "2-S-1"
        let valid_no_footer = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw";
        // "2-S-2"
        let valid_with_footer = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Public, V2>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Public, V2>::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[cfg(feature = "v3")]
    #[test]
    fn valid_v3_public() {
        // "3-S-1"
        let valid_no_footer = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph";
        // "3-S-2"
        let valid_with_footer = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9";

        let untrusted_no_footer = UntrustedToken::<Public, V3>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Public, V3>::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}".as_bytes()
        );
    }

    #[cfg(feature = "v4")]
    #[test]
    fn valid_v4_public() {
        // "4-S-1"
        let valid_no_footer = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA";
        // "4-S-2"
        let valid_with_footer = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Public, V4>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Public, V4>::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.untrusted_payload(),
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[cfg(feature = "v4")]
    #[test]
    fn valid_v4_local() {
        // "4-E-1"
        let valid_no_footer = "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg";
        // "4-E-5"
        let valid_with_footer = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::<Local, V4>::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer =
            UntrustedToken::<Local, V4>::try_from(valid_with_footer).unwrap();

        // Note: We don't test for untrusted message, since it is encrypted.
        assert_eq!(untrusted_no_footer.untrusted_footer(), &[0u8; 0]);
        assert_eq!(
            untrusted_with_footer.untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }

    #[test]
    fn local_token_nonce_tag_no_payload_v4() {
        assert!(UntrustedToken::<Local, V4>::try_from(
            "v4.local.444444bbbbb444444444bbb444444bbb44444444444444888888888888888cJJbbb44444444",
        )
        .is_err());
    }

    #[test]
    fn local_token_nonce_tag_no_payload_v3() {
        assert!(UntrustedToken::<Public, V3>::try_from(
            "v3.local.oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo",
        ).is_err());
    }

    #[test]
    fn test_get_footer_from_trusted() {
        let mut footer = Footer::default();
        footer.add_additional("t", "v").unwrap();
        let mut tt = TrustedToken::_new(
            "v3.local.",
            b"test msg",
            footer.to_string().unwrap().as_bytes(),
            b"",
        )
        .unwrap();
        assert!(Footer::try_from(&tt).is_ok());
        tt.footer = Vec::<u8>::new();
        assert!(Footer::try_from(&tt).is_err());
    }

    #[test]
    fn test_trusted_claims() {
        let mut footer = Footer::default();
        footer.add_additional("t", "v").unwrap();
        let mut tt = TrustedToken::_new(
            "v3.local.",
            b"test msg",
            footer.to_string().unwrap().as_bytes(),
            b"",
        )
        .unwrap();
        let claims = Claims::new().unwrap();
        tt.set_payload_claims(claims.clone());

        assert_eq!(tt.payload_claims.unwrap(), claims);
    }
}
