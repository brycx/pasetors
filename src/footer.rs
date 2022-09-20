#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

use crate::errors::Error;
#[cfg(feature = "paserk")]
use crate::paserk::{FormatAsPaserk, Id};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Clone)]
/// A footer with optional claims that are JSON-encoded.
pub struct Footer {
    list_of: HashMap<String, Value>,
    max_keys: usize,
    max_len: usize,
}

impl Default for Footer {
    fn default() -> Self {
        Self::new()
    }
}

impl Footer {
    /// Keys for registered claims in the footer, that are reserved for usage by PASETO in top-level.
    pub const REGISTERED_CLAIMS: [&'static str; 2] = ["kid", "wpk"];

    /// All PASERK types that are (implemented in this library) unsafe in the footer.
    pub const DISALLOWED_FOOTER: [&'static str; 8] = [
        "k2.local.",
        "k4.local.",
        "k2.secret.",
        "k3.secret.",
        "k4.secret.",
        "k2.public.",
        "k3.public.",
        "k4.public.",
    ];

    /// See [PASETO docs] for the reason behind this limit.
    ///
    /// Maximum number of named keys within an object.
    ///
    /// [PASETO docs]: https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string
    pub const DEFAULT_MAX_KEYS: usize = 512;

    /// See [PASETO docs] for the reason behind this limit.
    ///
    /// Maximum length of the JSON-encoded string.
    ///
    /// [PASETO docs]: https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string
    pub const DEFAULT_MAX_LEN: usize = 8192;

    /// See [PASETO docs] for the reason behind this limit.
    ///
    /// This value has been set by `serde_json` and cannot be changed.
    ///
    /// [PASETO docs]: https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string
    pub const MAX_RECURSION_DEPTH: usize = 128;

    /// Create a new `Footer` instance.
    pub fn new() -> Self {
        Self {
            list_of: HashMap::new(),
            max_keys: Self::DEFAULT_MAX_KEYS,
            max_len: Self::DEFAULT_MAX_LEN,
        }
    }

    /// Change the default (512) amount of maximum number of named keys within an object.
    ///
    /// __NOTE__: There should be no need to change this if you don't know this is a specific problem for you.
    pub fn max_keys(&mut self, max_keys: usize) {
        self.max_keys = max_keys;
    }

    /// Change the default (8192) amount of maximum number of named keys within an object.
    ///
    /// __NOTE__: There should be no need to change this if you don't know this is a specific problem for you.
    pub fn max_len(&mut self, max_len: usize) {
        self.max_len = max_len;
    }

    /// Add additional claims. If `claim` already exists, it is replaced with the new.
    ///
    /// Errors:
    /// - `claim` is a reserved claim (see [`Self::REGISTERED_CLAIMS`])
    /// - `value` is any of (starts with) the disallowed PASERK types (see [`Self::DISALLOWED_FOOTER`]).
    pub fn add_additional(&mut self, claim: &str, value: &str) -> Result<(), Error> {
        for unsafe_value in Self::DISALLOWED_FOOTER {
            if value.starts_with(unsafe_value) {
                return Err(Error::InvalidClaim);
            }
        }

        if !Self::REGISTERED_CLAIMS.contains(&claim) {
            self.list_of.insert(claim.into(), value.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Checks whether a specific claim has been added to the list.
    ///
    /// E.g `contains_claim("kid") == true` if `kid` has been added before.
    pub fn contains_claim(&self, claim: &str) -> bool {
        self.list_of.contains_key(claim)
    }

    /// Return Some(claim value) if claims list contains the `claim`.
    /// None otherwise.
    pub fn get_claim(&self, claim: &str) -> Option<&Value> {
        self.list_of.get(claim)
    }

    #[cfg(feature = "paserk")]
    /// Set the `kid` claim. If it already exists, replace it with the new.
    pub fn key_id(&mut self, id: &Id) {
        let mut paserk_kid = String::new();
        id.fmt(&mut paserk_kid).unwrap();

        self.list_of.insert("kid".into(), paserk_kid.into());
    }

    /// Attempt to create `Footer` from a sequence of bytes.
    ///
    /// Errors:
    /// - `bytes` contains non-UTF-8 sequences
    /// - `bytes` does not decode as valid JSON
    /// - `bytes` top-most JSON object does not decode to a map
    /// - if any registered claims exist and they are not a `String`
    /// - Parsing JSON maps and arrays that are more than 128 layers deep
    /// - Maximum number of named keys is exceeded
    /// - Maximum JSON-encoded string length is exceeded
    pub fn parse_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let input = bytes.to_vec();

        self.parse_string(&String::from_utf8(input).map_err(|_| Error::FooterParsing)?)
    }

    /// Attempt to parse a `Footer` from a string.
    ///
    /// Errors:
    /// - `string` does not decode as valid JSON
    /// - `string` top-most JSON object does not decode to a map
    /// - if any registered claims exist and they are not a `String`
    /// - Parsing JSON maps and arrays that are more than 128 layers deep
    /// - Maximum number of named keys is exceeded
    /// - Maximum JSON-encoded string length is exceeded
    pub fn parse_string(&mut self, string: &str) -> Result<(), Error> {
        if string.len() > self.max_len {
            return Err(Error::FooterParsing);
        }
        if Regex::new(r#"[^\\]":"#).unwrap().find_iter(string).count() > self.max_keys {
            return Err(Error::FooterParsing);
        }

        self.list_of = serde_json::from_str(string).map_err(|_| Error::FooterParsing)?;

        Ok(())
    }

    /// Return the JSON serialized representation of `Self`.
    ///
    /// Errors:
    /// - `self` cannot be serialized as JSON
    pub fn to_string(&self) -> Result<String, Error> {
        match serde_json::to_string(&self.list_of) {
            Ok(ret) => Ok(ret),
            Err(_) => Err(Error::FooterParsing),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::footer::Footer;
    use regex::Regex;

    #[test]
    fn test_count_keys() {
        // https://www.rustescaper.com/
        let string = r#""name": "3-S-2",
      "expect-fail": false,
      "public-key": "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
      "secret-key": "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
      "secret-key-pem": "-----BEGIN EC PRIVATE KEY-----nMIGkAgEBBDAgNHYJYHR3rKj7+8XmIYRV8xmWaXku+LRm+qh73Gd5gUTISN0DZh7tnWsYkYTQM6pagBwYFK4EEACKhZANiAAT7y3xp7hxgV5vnozQTSHjZxcW/NdVS2rY8nAUA5ftFM72N9dyCSXERpnqMOcodMcvt8kgcrB8KcKee0HU23E79/s4CvEs8hBfnjnSUd/gcAm08EjSIz06iWjrNy4NakxR3I=n-----END EC PRIVATE KEY-----",
      "public-key-pem": "-----BEGIN PUBLIC KEY-----nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+8t8ae4cYFeb56M0E0h42cXFvzXVUtq2nPAFAOX7RTO9jfXcgklxEaZ6jDnKHTHL7fJIHKwfCnCnntB1NtxO/f7OArxLPIQX5n40lHf4HAJtPBI0iM9Oolo6zcuDWpMUdyn-----END PUBLIC KEY-----",
      "token": "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
      "payload": "{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}",
      "footer": "{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}",
      "implicit-assertion": """#;

        assert_eq!(
            Regex::new(r#"[^\\]":"#).unwrap().find_iter(string).count(),
            13
        );
    }

    #[test]
    fn err_on_max_keys() {
        let mut footer = Footer::default();
        for n in 1..=11 {
            footer
                .add_additional(format!("{}", n).as_str(), "test")
                .unwrap();
        }

        let mut footer_parse = Footer::default();
        footer_parse.max_keys(10);
        assert!(footer_parse
            .parse_bytes(footer.to_string().unwrap().as_bytes())
            .is_err());
    }

    #[test]
    fn err_on_max_len() {
        let mut footer = Footer::new();
        for n in 1..=11 {
            footer
                .add_additional(format!("{}", n).as_str(), "test")
                .unwrap();
        }
        let ser_footer = footer.to_string().unwrap();

        let mut footer_parse = Footer::new();
        footer_parse.max_len(ser_footer.len() - 1);
        assert!(footer_parse.parse_bytes(ser_footer.as_bytes()).is_err());
    }

    #[test]
    fn err_on_custom_with_registered() {
        let mut footer = Footer::new();

        assert!(footer.add_additional("wpk", "test").is_err());
        assert!(footer.add_additional("kid", "test").is_err());
        assert!(footer.add_additional("custom", "test").is_ok());
    }

    #[test]
    #[cfg(all(feature = "paserk", feature = "v2", feature = "v3", feature = "v4"))]
    fn err_on_disallowed_in_footer() {
        use crate::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
        use crate::paserk::FormatAsPaserk;
        use crate::version2::V2;
        use crate::version3::V3;
        use crate::version4::V4;

        let mut footer = Footer::new();

        let kpv2 = AsymmetricKeyPair::<V2>::generate().unwrap();
        let kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        let kpv4 = AsymmetricKeyPair::<V4>::generate().unwrap();
        let skv2 = SymmetricKey::<V2>::generate().unwrap();
        let skv4 = SymmetricKey::<V4>::generate().unwrap();

        let mut buf = String::new();
        kpv2.secret.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv2.public.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv3.secret.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv3.public.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv4.secret.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        kpv4.public.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        skv2.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());

        let mut buf = String::new();
        skv4.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("wpk", &buf).is_err());
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_err());
    }

    #[test]
    #[cfg(all(feature = "paserk", feature = "v2", feature = "v3", feature = "v4"))]
    fn kid_in_footer() {
        use crate::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
        use crate::paserk::{FormatAsPaserk, Id};
        use crate::version2::V2;
        use crate::version3::V3;
        use crate::version4::V4;

        let mut footer = Footer::new();

        let kpv2 = AsymmetricKeyPair::<V2>::generate().unwrap();
        let kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        let kpv4 = AsymmetricKeyPair::<V4>::generate().unwrap();
        let skv2 = SymmetricKey::<V2>::generate().unwrap();
        let skv4 = SymmetricKey::<V4>::generate().unwrap();

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv2.secret);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv2.public);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv3.secret);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv3.public);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv4.secret);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&kpv4.public);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&skv2);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);

        let mut buf = String::new();
        let paserk_id = Id::from(&skv4);
        paserk_id.fmt(&mut buf).unwrap();
        assert!(footer.add_additional("kid", &buf).is_err());
        assert!(footer.add_additional("custom", &buf).is_ok());
        footer.key_id(&paserk_id);
        assert!(footer.contains_claim("kid"));
        assert_eq!(footer.get_claim("kid").unwrap().as_str().unwrap(), buf);
    }
}
