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
    /// If it is a local token, this is the encrypted message.
    /// If it is a public token, the signature is included.
    pub fn get_untrusted_message(&self) -> &[u8] {
        &self.message
    }

    /// Return untrusted footer of this [`UntrustedToken].
    /// Empty if there was no footer in the token.
    pub fn get_untrusted_footer(&self) -> &[u8] {
        &self.footer
    }
}

#[cfg(test)]
mod tests {
    use crate::token::UntrustedToken;
    use std::convert::TryFrom;

    #[test]
    fn invalid_tokens() {
        assert!(UntrustedToken::try_from("v2.public.AAAAA%%%").is_err());
        assert!(UntrustedToken::try_from("v2.depends.AAAAAAAA").is_err());
        assert!(UntrustedToken::try_from("v999.public.AAAAA%%%").is_err());
        assert!(UntrustedToken::try_from("v2.").is_err());
        assert!(UntrustedToken::try_from("v2.public").is_err());
    }

    #[cfg(feature = "v2")]
    #[test]
    fn valid_v2_local() {
        // "2-E-1"
        let valid_no_footer = "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ";
        // "2-E-5"
        let valid_with_footer = "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        let untrusted_no_footer = UntrustedToken::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer = UntrustedToken::try_from(valid_with_footer).unwrap();

        // Note: We don't test for untrusted message, since it is encrypted.
        assert_eq!(
            untrusted_no_footer.get_untrusted_header(),
            crate::version2::LocalToken::HEADER
        );
        assert_eq!(untrusted_no_footer.get_untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.get_untrusted_header(),
            crate::version2::LocalToken::HEADER
        );
        assert_eq!(
            untrusted_with_footer.get_untrusted_footer(),
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

        let untrusted_no_footer = UntrustedToken::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer = UntrustedToken::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.get_untrusted_header(),
            crate::version2::PublicToken::HEADER
        );

        let msg_len = untrusted_no_footer.get_untrusted_message().len();
        assert_eq!(
            &untrusted_no_footer.get_untrusted_message()[..msg_len - 64],
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.get_untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.get_untrusted_header(),
            crate::version2::PublicToken::HEADER
        );
        assert_eq!(
            &untrusted_with_footer.get_untrusted_message()[..msg_len - 64],
            "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.get_untrusted_footer(),
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

        let untrusted_no_footer = UntrustedToken::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer = UntrustedToken::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.get_untrusted_header(),
            crate::version3::PublicToken::HEADER
        );

        let msg_len = untrusted_no_footer.get_untrusted_message().len();
        assert_eq!(
            &untrusted_no_footer.get_untrusted_message()[..msg_len - 96],
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.get_untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.get_untrusted_header(),
            crate::version3::PublicToken::HEADER
        );
        assert_eq!(
            &untrusted_with_footer.get_untrusted_message()[..msg_len - 96],
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.get_untrusted_footer(),
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

        let untrusted_no_footer = UntrustedToken::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer = UntrustedToken::try_from(valid_with_footer).unwrap();

        assert_eq!(
            untrusted_no_footer.get_untrusted_header(),
            crate::version4::PublicToken::HEADER
        );

        let msg_len = untrusted_no_footer.get_untrusted_message().len();
        assert_eq!(
            &untrusted_no_footer.get_untrusted_message()[..msg_len - 64],
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(untrusted_no_footer.get_untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.get_untrusted_header(),
            crate::version4::PublicToken::HEADER
        );
        assert_eq!(
            &untrusted_with_footer.get_untrusted_message()[..msg_len - 64],
            "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}"
                .as_bytes()
        );
        assert_eq!(
            untrusted_with_footer.get_untrusted_footer(),
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

        let untrusted_no_footer = UntrustedToken::try_from(valid_no_footer).unwrap();
        let untrusted_with_footer = UntrustedToken::try_from(valid_with_footer).unwrap();

        // Note: We don't test for untrusted message, since it is encrypted.
        assert_eq!(
            untrusted_no_footer.get_untrusted_header(),
            crate::version4::LocalToken::HEADER
        );
        assert_eq!(untrusted_no_footer.get_untrusted_footer(), &[0u8; 0]);

        assert_eq!(
            untrusted_with_footer.get_untrusted_header(),
            crate::version4::LocalToken::HEADER
        );
        assert_eq!(
            untrusted_with_footer.get_untrusted_footer(),
            "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}".as_bytes()
        );
    }
}
