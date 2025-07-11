#![cfg_attr(docsrs, doc(cfg(feature = "std")))]

use crate::errors::{ClaimValidationError, Error};
use core::convert::TryFrom;
use serde_json::Value;
use std::collections::HashMap;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Serialize, serde_derive::Deserialize)
)]
/// A collection of claims that are passed as payload for a PASETO token.
pub struct Claims {
    #[cfg_attr(feature = "serde", serde(flatten))]
    list_of: HashMap<String, Value>,
}

impl Claims {
    /// Keys for registered claims, that are reserved for usage by PASETO in top-level.
    pub const REGISTERED_CLAIMS: [&'static str; 7] =
        ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

    /// Create a new `Claims` instance, setting:
    /// - `iat`, `nbf` to current UTC time
    /// - `exp` to one hour
    ///
    /// Errors:
    /// - If adding current time with one hour would overflow
    pub fn new() -> Result<Self, Error> {
        Self::new_expires_in(&core::time::Duration::from_secs(3600))
    }

    /// Create a new `Claims` instance expiring in `duration`, setting:
    /// - `iat`, `nbf` to current UTC time
    /// - `iat + duration`
    ///
    /// Errors:
    /// - If adding current time with `duration` would overflow
    /// - If `core::time::Duration` failed to convert to `time::Duration`
    pub fn new_expires_in(duration: &core::time::Duration) -> Result<Self, Error> {
        let mut claims = Self {
            list_of: HashMap::new(),
        };

        claims.set_expires_in(duration)?;

        Ok(claims)
    }

    /// Format a DateTime claim in ISO 8601 without fractional seconds.
    ///
    /// Omitting fractional seconds is recommended by PASETO spec:
    /// > While arbitrary fractional seconds SHOULD be supported in parsers, is RECOMMENDED to omit them on creation.
    fn format_datetime(time: OffsetDateTime) -> Result<String, Error> {
        time.replace_nanosecond(0)
            .map_err(|_| Error::InvalidClaim)?
            .format(&Rfc3339)
            .map_err(|_| Error::InvalidClaim)
    }

    /// Set `iat`, `nbf`, `exp` claims expiring in `duration`, setting:
    /// - `iat`, `nbf` to current UTC time
    /// - `iat + duration`
    ///
    /// Errors:
    /// - If adding current time with `duration` would overflow
    /// - If `core::time::Duration` failed to convert to `time::Duration`
    pub fn set_expires_in(&mut self, duration: &core::time::Duration) -> Result<(), Error> {
        let iat = OffsetDateTime::now_utc();
        let nbf = iat;
        let mut exp = iat;
        exp += Duration::try_from(*duration).map_err(|_| Error::InvalidClaim)?;

        self.issued_at(&Self::format_datetime(iat)?)?;
        self.not_before(&Self::format_datetime(nbf)?)?;
        self.expiration(&Self::format_datetime(exp)?)?;

        Ok(())
    }

    /// Removes the `exp` claim, indicating a token that never expires.
    pub fn non_expiring(&mut self) {
        self.remove_claim("exp");
    }

    /// Add additional claims. If `claim` already exists, it is replaced with the new.
    ///
    /// Errors:
    /// - `claim` is a reserved claim (see [`Self::REGISTERED_CLAIMS`])
    pub fn add_additional(&mut self, claim: &str, value: impl Into<Value>) -> Result<(), Error> {
        if !Self::REGISTERED_CLAIMS.contains(&claim) {
            self.list_of.insert(claim.into(), value.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Checks whether a specific claim has been added to the list.
    ///
    /// E.g `contains_claim("iss") == true` if `iss` has been added before.
    pub fn contains_claim(&self, claim: &str) -> bool {
        self.list_of.contains_key(claim)
    }

    /// Return Some(claim value) if claims list contains the `claim`.
    /// None otherwise.
    pub fn get_claim(&self, claim: &str) -> Option<&Value> {
        self.list_of.get(claim)
    }

    /// Remove a claim from the claims list.
    ///
    /// Return Some(claim value) if claims list contains the `claim`.
    /// None otherwise.
    pub fn remove_claim(&mut self, claim: &str) -> Option<Value> {
        self.list_of.remove(claim)
    }

    /// Set the `iss` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `iss` is empty
    pub fn issuer(&mut self, iss: &str) -> Result<(), Error> {
        if !iss.is_empty() {
            self.list_of.insert("iss".into(), iss.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Set the `sub` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `sub` is empty
    pub fn subject(&mut self, sub: &str) -> Result<(), Error> {
        if !sub.is_empty() {
            self.list_of.insert("sub".into(), sub.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Set the `aud` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `aud` is empty
    pub fn audience(&mut self, aud: &str) -> Result<(), Error> {
        if !aud.is_empty() {
            self.list_of.insert("aud".into(), aud.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Set the `exp` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `exp` is empty
    /// - `exp` cannot be parsed as a ISO 8601 compliant DateTime string.
    pub fn expiration(&mut self, exp: &str) -> Result<(), Error> {
        if let Ok(_exp_str) = OffsetDateTime::parse(exp, &Rfc3339) {
            self.list_of.insert("exp".into(), exp.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Set the `nbf` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `nbf` is empty
    /// - `nbf` cannot be parsed as a ISO 8601 compliant DateTime string.
    pub fn not_before(&mut self, nbf: &str) -> Result<(), Error> {
        if let Ok(_nbf_str) = OffsetDateTime::parse(nbf, &Rfc3339) {
            self.list_of.insert("nbf".into(), nbf.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Set the `iat` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `iat` is empty
    /// - `iat` cannot be parsed as a ISO 8601 compliant DateTime string.
    pub fn issued_at(&mut self, iat: &str) -> Result<(), Error> {
        if let Ok(_iat_str) = OffsetDateTime::parse(iat, &Rfc3339) {
            self.list_of.insert("iat".into(), iat.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Set the `jti` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `jti` is empty
    pub fn token_identifier(&mut self, jti: &str) -> Result<(), Error> {
        if !jti.is_empty() {
            self.list_of.insert("jti".into(), jti.into());
            Ok(())
        } else {
            Err(Error::InvalidClaim)
        }
    }

    /// Attempt to create `Claims` from a sequence of bytes.
    ///
    /// Errors:
    /// - `bytes` contains non-UTF-8 sequences
    /// - `bytes` does not decode as valid JSON
    /// - `bytes` top-most JSON object does not decode to a map
    /// - if any registered claims exist and they are not a `String`
    /// - if `exp`, `nbf` or `iat` exist and they cannot be parsed as `DateTime`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let input = bytes.to_vec();

        Self::from_string(&String::from_utf8(input).map_err(|_| Error::ClaimInvalidUtf8)?)
    }

    /// Attempt to create `Claims` from a string.
    ///
    /// Errors:
    /// - `string` does not decode as valid JSON
    /// - `string` top-most JSON object does not decode to a map
    /// - if any registered claims exist and they are not a `String`
    /// - if `exp`, `nbf` or `iat` exist and they cannot be parsed as `DateTime`
    pub fn from_string(string: &str) -> Result<Self, Error> {
        let list_of: HashMap<String, Value> =
            serde_json::from_str(string).map_err(|_| Error::ClaimInvalidJson)?;

        // Validate any possible registered claims for their type
        for registered_claim in Self::REGISTERED_CLAIMS {
            if let Some(claim) = list_of.get(registered_claim) {
                if let Some(claim_value) = claim.as_str() {
                    if registered_claim == "exp"
                        || registered_claim == "nbf"
                        || registered_claim == "iat"
                    {
                        OffsetDateTime::parse(claim_value, &Rfc3339)
                            .map_err(|_| Error::InvalidClaim)?;
                    }
                } else {
                    return Err(Error::InvalidClaim);
                }
            }
        }

        Ok(Self { list_of })
    }

    /// Return the JSON serialized representation of `Self`.
    ///
    /// Errors:
    /// - `self` cannot be serialized as JSON
    pub fn to_string(&self) -> Result<String, Error> {
        match serde_json::to_string(&self.list_of) {
            Ok(ret) => Ok(ret),
            Err(_) => Err(Error::ClaimInvalidJson),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// The validation rules that are used to validate a set of [`Claims`].
pub struct ClaimsValidationRules {
    validate_currently_valid: bool,
    allow_non_expiring: bool,
    validate_issuer: Option<String>,
    validate_subject: Option<String>,
    validate_audience: Option<String>,
    validate_token_identifier: Option<String>,
}

impl Default for ClaimsValidationRules {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaimsValidationRules {
    /// Create a new `ClaimsValidationRules` instance, setting:
    /// - validation of `iat`, `nbf`, `exp` true
    pub fn new() -> Self {
        Self {
            validate_currently_valid: true,
            allow_non_expiring: false,
            validate_issuer: None,
            validate_subject: None,
            validate_audience: None,
            validate_token_identifier: None,
        }
    }

    /// Disables the validation of `iat` and `nbf`, from the `ValidAt` validation pattern.
    ///
    /// `iat` and `nbf` may still be present in the [`Claims`] payload, at validation time, but will not be parsed.
    /// This means, you can disable this validation without modifying the creation of your [`Claims`].
    /// In case of using `allow_non_expiring()`, the validation expects no `exp` claim to be present within the payload.
    ///
    /// To disable the entire `ValidAt` pattern, specify also `allow_non_expiring()`.
    ///
    /// See [PASETO Validators](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md).
    pub fn disable_valid_at(&mut self) {
        self.validate_currently_valid = false;
    }

    /// Explicitly allow non-expiring tokens (i.e. the `exp` claim is missing).
    pub fn allow_non_expiring(&mut self) {
        self.allow_non_expiring = true;
    }

    /// Set the `valid_issuer` the claims should be validated against.
    pub fn validate_issuer_with(&mut self, valid_issuer: &str) {
        self.validate_issuer = Some(valid_issuer.to_string());
    }

    /// Set the `valid_subject` the claims should be validated against.
    pub fn validate_subject_with(&mut self, valid_subject: &str) {
        self.validate_subject = Some(valid_subject.to_string());
    }

    /// Set the `valid_audience` the claims should be validated against.
    pub fn validate_audience_with(&mut self, valid_audience: &str) {
        self.validate_audience = Some(valid_audience.to_string());
    }

    /// Set the `valid_token_identifier` the claims should be validated against.
    pub fn validate_token_identifier_with(&mut self, valid_token_identifier: &str) {
        self.validate_token_identifier = Some(valid_token_identifier.to_string());
    }

    /// Validate the set of registered `claims` against the currently defined validation rules.
    ///
    /// If `claims` has defined the `exp` claim, this is validated regardless of whether the rules
    /// have allowed for non-expiring. Non-expiring means that there should be no `exp` in `claims`.
    ///
    /// Errors:
    /// - Token is expired
    /// - Token is not yet valid
    /// - Token was issued in the future
    /// - Token has no `exp` claim but the validation rules do not allow non-expiring tokens
    /// - The claims values cannot be converted to `str`
    /// - `iat`, `nbf` and `exp` fail `str -> DateTime` conversion
    /// - Claim `iss`, `sub`, `aud`, `jti` does not match the expected
    /// - `claims` has no `nbf` or `iat` (unless [`Self::disable_valid_at()`] has been set)
    /// - a claim was registered for validation in the rules but is missing from the actual `claims`
    ///
    /// NOTE: This __does not__ validate any non-registered claims (see [`Claims::REGISTERED_CLAIMS`]). They must be validated
    /// separately.
    pub fn validate_claims(&self, claims: &Claims) -> Result<(), Error> {
        if self.validate_currently_valid {
            let current_time = OffsetDateTime::now_utc();

            if let Some(nbf) = claims.list_of.get("nbf") {
                if let Some(nbf) = nbf.as_str() {
                    let nbf = OffsetDateTime::parse(nbf, &Rfc3339)
                        .map_err(|_| Error::ClaimValidation(ClaimValidationError::ParseNbf))?;
                    if current_time < nbf {
                        return Err(Error::ClaimValidation(ClaimValidationError::Nbf));
                    }
                } else {
                    return Err(Error::ClaimValidation(ClaimValidationError::NoStrNbf));
                }
            } else {
                return Err(Error::ClaimValidation(ClaimValidationError::NoNbf));
            }

            if let Some(iat) = claims.list_of.get("iat") {
                if let Some(iat) = iat.as_str() {
                    let iat = OffsetDateTime::parse(iat, &Rfc3339)
                        .map_err(|_| Error::ClaimValidation(ClaimValidationError::ParseIat))?;
                    if current_time < iat {
                        return Err(Error::ClaimValidation(ClaimValidationError::Iat));
                    }
                } else {
                    return Err(Error::ClaimValidation(ClaimValidationError::NoStrIat));
                }
            } else {
                return Err(Error::ClaimValidation(ClaimValidationError::NoIat));
            }
        }

        if let Some(exp) = claims.list_of.get("exp") {
            if let Some(exp) = exp.as_str() {
                let exp = OffsetDateTime::parse(exp, &Rfc3339)
                    .map_err(|_| Error::ClaimValidation(ClaimValidationError::ParseExp))?;
                let current_time = OffsetDateTime::now_utc();

                if current_time > exp {
                    return Err(Error::ClaimValidation(ClaimValidationError::Exp));
                }
            } else {
                return Err(Error::ClaimValidation(ClaimValidationError::NoStrExp));
            }
        } else if !self.allow_non_expiring {
            // We didn't explicitly allow non-expiring tokens so we expect `exp` claim.
            return Err(Error::ClaimValidation(ClaimValidationError::NoExp));
        }

        if let Some(expected_issuer) = &self.validate_issuer {
            if let Some(actual_issuer) = claims.list_of.get("iss") {
                if expected_issuer != actual_issuer {
                    return Err(Error::ClaimValidation(ClaimValidationError::Iss));
                }
            } else {
                return Err(Error::ClaimValidation(ClaimValidationError::NoIss));
            }
        }

        if let Some(expected_subject) = &self.validate_subject {
            if let Some(actual_subject) = claims.list_of.get("sub") {
                if expected_subject != actual_subject {
                    return Err(Error::ClaimValidation(ClaimValidationError::Sub));
                }
            } else {
                return Err(Error::ClaimValidation(ClaimValidationError::NoSub));
            }
        }

        if let Some(expected_audience) = &self.validate_audience {
            if let Some(actual_audience) = claims.list_of.get("aud") {
                if expected_audience != actual_audience {
                    return Err(Error::ClaimValidation(ClaimValidationError::Aud));
                }
            } else {
                return Err(Error::ClaimValidation(ClaimValidationError::NoAud));
            }
        }

        if let Some(expected_token_identifier) = &self.validate_token_identifier {
            if let Some(actual_token_identifier) = claims.list_of.get("jti") {
                if expected_token_identifier != actual_token_identifier {
                    return Err(Error::ClaimValidation(ClaimValidationError::Jti));
                }
            } else {
                return Err(Error::ClaimValidation(ClaimValidationError::NoJti));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_empty_claim_value() {
        let mut claims = Claims::new().unwrap();

        assert!(claims.issuer("").is_err());
        assert!(claims.subject("").is_err());
        assert!(claims.audience("").is_err());
        assert!(claims.expiration("").is_err());
        assert!(claims.not_before("").is_err());
        assert!(claims.issued_at("").is_err());
        assert!(claims.token_identifier("").is_err());
    }

    #[test]
    fn test_error_on_arbitrary_registered() {
        let mut claims = Claims::new().unwrap();

        assert!(claims.add_additional("iss", "test").is_err());
        assert!(claims.add_additional("sub", "test").is_err());
        assert!(claims.add_additional("aud", "test").is_err());
        assert!(claims
            .add_additional("exp", "2014-11-28T21:00:09+09:00")
            .is_err());
        assert!(claims
            .add_additional("nbf", "2014-11-28T21:00:09+09:00")
            .is_err());
        assert!(claims
            .add_additional("iat", "2014-11-28T21:00:09+09:00")
            .is_err());
        assert!(claims.add_additional("jti", "test").is_err());

        assert!(claims.add_additional("not_reserved", "test").is_ok());
    }

    #[test]
    fn test_failed_datetime_parsing() {
        let mut claims = Claims::new().unwrap();

        assert!(claims
            .expiration("this is not a ISO 8601 DateTime string")
            .is_err());
        assert!(claims
            .not_before("this is not a ISO 8601 DateTime string")
            .is_err());
        assert!(claims
            .issued_at("this is not a ISO 8601 DateTime string")
            .is_err());

        claims.list_of.insert(
            "iat".to_string(),
            "this is not a ISO 8601 DateTime string".into(),
        );
        claims.list_of.insert(
            "nbf".to_string(),
            "this is not a ISO 8601 DateTime string".into(),
        );

        let validation_rules = ClaimsValidationRules::default();
        assert!(validation_rules.validate_claims(&claims).is_err());
    }

    #[test]
    fn test_datetime_fractional_seconds() {
        let mut claims = Claims::new().unwrap();

        // Omitting fractional seconds on creation
        const LEN: usize = "2025-06-24T18:03:53Z".len();
        assert_eq!(
            claims.get_claim("exp").unwrap().as_str().unwrap().len(),
            LEN
        );
        assert_eq!(
            claims.get_claim("nbf").unwrap().as_str().unwrap().len(),
            LEN
        );
        assert_eq!(
            claims.get_claim("iat").unwrap().as_str().unwrap().len(),
            LEN
        );

        // Arbitrary fractional seconds SHOULD be supported in parsers
        assert!(claims.expiration("9999-01-01T00:00:00Z").is_ok());
        assert!(claims.not_before("1970-01-01T00:00:00+00:00").is_ok());
        assert!(claims.issued_at("1970-01-01T00:00:00+00:00").is_ok());

        let validation_rules = ClaimsValidationRules::default();
        assert!(validation_rules.validate_claims(&claims).is_ok());

        assert!(claims
            .expiration("9999-01-01T00:00:00.1234567890123456789012345678901234567890+00:00")
            .is_ok());
        assert!(claims
            .not_before("1970-01-01T00:00:00.1234567890123456789012345678901234567890Z")
            .is_ok());
        assert!(claims
            .issued_at("1970-01-01T00:00:00.1234567890123456789012345678901234567890+00:00")
            .is_ok());

        let validation_rules = ClaimsValidationRules::default();
        assert!(validation_rules.validate_claims(&claims).is_ok());
    }

    #[test]
    fn test_contains_claim() {
        let mut claims = Claims::new().unwrap();

        // Default claims
        assert!(claims.contains_claim("iat"));
        assert!(claims.contains_claim("nbf"));
        assert!(claims.contains_claim("exp"));

        assert!(!claims.contains_claim("iss"));
        claims.issuer("testIssuer").unwrap();
        assert!(claims.contains_claim("iss"));

        assert!(!claims.contains_claim("aud"));
        claims.audience("testAudience").unwrap();
        assert!(claims.contains_claim("aud"));
    }

    #[test]
    fn test_basic_claims_validation() {
        // Set all claims plus a custom one
        let mut claims = Claims::new().unwrap();
        claims.issuer("testIssuer").unwrap();
        claims.audience("testAudience").unwrap();
        claims.subject("testSubject").unwrap();
        claims.token_identifier("testIdentifier").unwrap();
        claims.add_additional("testClaim", "testValue").unwrap();

        let mut claims_validation = ClaimsValidationRules::new();
        claims_validation.validate_issuer_with("testIssuer");
        claims_validation.validate_audience_with("testAudience");
        claims_validation.validate_subject_with("testSubject");
        claims_validation.validate_token_identifier_with("testIdentifier");

        assert!(&claims_validation.validate_claims(&claims).is_ok());

        // Mismatch between Claims `iss` and ClaimValidationRules `iss`
        claims_validation.validate_issuer_with("testIssuerFalse");
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims_validation.validate_issuer_with("testIssuer");
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims
            .list_of
            .insert("iss".to_string(), "testIssuerFalse".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("iss".to_string(), "testIssuer".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims.list_of.remove_entry("iss").unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("iss".to_string(), "testIssuer".into());
        assert!(&claims_validation.validate_claims(&claims).is_ok());

        // Mismatch between Claims `aud` and ClaimValidationRules `aud`
        claims_validation.validate_audience_with("testAudienceFalse");
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims_validation.validate_audience_with("testAudience");
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims
            .list_of
            .insert("aud".to_string(), "testAudienceFalse".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("aud".to_string(), "testAudience".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims.list_of.remove_entry("aud").unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("aud".to_string(), "testAudience".into());
        assert!(&claims_validation.validate_claims(&claims).is_ok());

        // Mismatch between Claims `sub` and ClaimValidationRules `sub`
        claims_validation.validate_subject_with("testSubjectFalse");
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims_validation.validate_subject_with("testSubject");
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims
            .list_of
            .insert("sub".to_string(), "testSubjectFalse".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("sub".to_string(), "testSubject".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims.list_of.remove_entry("sub").unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("sub".to_string(), "testSubject".into());
        assert!(&claims_validation.validate_claims(&claims).is_ok());

        // Mismatch between Claims `jti` and ClaimValidationRules `jti`
        claims_validation.validate_token_identifier_with("testIdentifierFalse");
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims_validation.validate_token_identifier_with("testIdentifier");
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims
            .list_of
            .insert("jti".to_string(), "testIdentifierFalse".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("jti".to_string(), "testIdentifier".into())
            .unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_ok());
        claims.list_of.remove_entry("jti").unwrap();
        assert!(&claims_validation.validate_claims(&claims).is_err());
        claims
            .list_of
            .insert("jti".to_string(), "testIdentifier".into());
        assert!(&claims_validation.validate_claims(&claims).is_ok());
    }

    #[test]
    fn test_invalid_token_at_time() {
        let claims = Claims::new().unwrap();
        let claims_validation = ClaimsValidationRules::new();

        assert!(claims_validation.validate_claims(&claims).is_ok());

        // Outdated
        let mut outdated_claims = claims.clone();
        outdated_claims
            .list_of
            .insert("iat".to_string(), "2019-01-01T00:00:00+00:00".into())
            .unwrap();
        assert!(claims_validation.validate_claims(&outdated_claims).is_ok());
        outdated_claims
            .list_of
            .insert("nbf".to_string(), "2019-01-01T00:00:00+00:00".into())
            .unwrap();
        assert!(claims_validation.validate_claims(&outdated_claims).is_ok());
        outdated_claims
            .list_of
            .insert("exp".to_string(), "2019-01-01T00:00:00+00:00".into())
            .unwrap();
        // Expired
        assert_eq!(
            claims_validation
                .validate_claims(&outdated_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::Exp)
        );
        outdated_claims.non_expiring();
        let mut claims_validation_allow_expiry = claims_validation.clone();
        // Rules not yet defined to allow non-expiring
        assert!(claims_validation_allow_expiry
            .validate_claims(&outdated_claims)
            .is_err());
        claims_validation_allow_expiry.allow_non_expiring();
        // Test if claim has `exp` but rules dictate allowing non-expiring (which is ignored
        // as long as `exp` is present in the claims) so it's still expired
        outdated_claims
            .expiration("2019-01-01T00:00:00+00:00")
            .unwrap();
        assert!(claims_validation_allow_expiry
            .validate_claims(&outdated_claims)
            .is_err());
        // Missing `exp` and allow in rules match
        outdated_claims.non_expiring();
        assert!(claims_validation_allow_expiry
            .validate_claims(&outdated_claims)
            .is_ok());

        // In-future
        let mut future_claims = claims.clone();
        let old_iat = future_claims
            .list_of
            .insert("iat".to_string(), "2028-01-01T00:00:00+00:00".into())
            .unwrap();
        // Issued in future
        assert_eq!(
            claims_validation
                .validate_claims(&future_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::Iat)
        );
        future_claims.issued_at(old_iat.as_str().unwrap()).unwrap();
        assert!(claims_validation.validate_claims(&future_claims).is_ok());
        // Not yet valid
        let old_nbf = future_claims
            .list_of
            .insert("nbf".to_string(), "2028-01-01T00:00:00+00:00".into())
            .unwrap();
        assert_eq!(
            claims_validation
                .validate_claims(&future_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::Nbf)
        );
        future_claims.not_before(old_nbf.as_str().unwrap()).unwrap();
        assert!(claims_validation.validate_claims(&future_claims).is_ok());

        // We expect `iat`, `exp` and `nbf` if we validate time
        let mut incomplete_claims = claims.clone();
        incomplete_claims.list_of.remove_entry("iat").unwrap();
        assert_eq!(
            claims_validation
                .validate_claims(&incomplete_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoIat)
        );

        let mut incomplete_claims = claims.clone();
        incomplete_claims.list_of.remove_entry("exp").unwrap();
        assert_eq!(
            claims_validation
                .validate_claims(&incomplete_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoExp)
        );

        let mut incomplete_claims = claims;
        incomplete_claims.list_of.remove_entry("nbf").unwrap();
        assert_eq!(
            claims_validation
                .validate_claims(&incomplete_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoNbf)
        );
    }

    #[test]
    fn test_skip_iat_nbf_validation() {
        let claims = Claims::new().unwrap();
        let claims_validation = ClaimsValidationRules::new();
        assert!(claims_validation.validate_claims(&claims).is_ok());

        let mut no_iat_claims = claims.clone();
        let mut no_nbf_claims = claims.clone();
        let mut no_iat_or_nbf_claims = claims.clone();
        let mut no_iat_nbf_claims_validation = claims_validation.clone();
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_iat_claims)
            .is_ok());
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_nbf_claims)
            .is_ok());
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_iat_or_nbf_claims)
            .is_ok());

        no_iat_claims.list_of.remove("iat").unwrap();
        no_nbf_claims.list_of.remove("nbf").unwrap();
        no_iat_or_nbf_claims.list_of.remove("iat").unwrap();
        no_iat_or_nbf_claims.list_of.remove("nbf").unwrap();
        // Normal validation fails without iat
        assert_eq!(
            claims_validation
                .validate_claims(&no_iat_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoIat)
        );
        // Normal validation fails without nbf
        assert_eq!(
            claims_validation
                .validate_claims(&no_nbf_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoNbf)
        );
        // Normal validation fails without iat and nbf
        assert_eq!(
            claims_validation
                .validate_claims(&no_iat_or_nbf_claims)
                .unwrap_err(),
            // Nbf is just the one checked first.
            Error::ClaimValidation(ClaimValidationError::NoNbf)
        );

        // Disable iat+nbf validation passes
        no_iat_nbf_claims_validation.disable_valid_at();
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_iat_claims)
            .is_ok());
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_nbf_claims)
            .is_ok());
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_iat_or_nbf_claims)
            .is_ok());

        // Check that expiry still is validated.
        no_iat_claims
            .list_of
            .insert("exp".to_string(), "2019-01-01T00:00:00+00:00".into())
            .unwrap();
        no_nbf_claims
            .list_of
            .insert("exp".to_string(), "2019-01-01T00:00:00+00:00".into())
            .unwrap();
        no_iat_or_nbf_claims
            .list_of
            .insert("exp".to_string(), "2019-01-01T00:00:00+00:00".into())
            .unwrap();
        assert_eq!(
            no_iat_nbf_claims_validation
                .validate_claims(&no_iat_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::Exp)
        );
        assert_eq!(
            no_iat_nbf_claims_validation
                .validate_claims(&no_nbf_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::Exp)
        );
        assert_eq!(
            no_iat_nbf_claims_validation
                .validate_claims(&no_iat_or_nbf_claims)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::Exp)
        );

        // Setting non_expiring() will validate them again
        no_iat_claims.non_expiring();
        no_nbf_claims.non_expiring();
        no_iat_or_nbf_claims.non_expiring();
        no_iat_nbf_claims_validation.allow_non_expiring();
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_iat_claims)
            .is_ok());
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_nbf_claims)
            .is_ok());
        assert!(no_iat_nbf_claims_validation
            .validate_claims(&no_iat_or_nbf_claims)
            .is_ok());
    }

    #[test]
    fn test_add_non_string_additional_claims() {
        // Set all claims plus a custom one
        let mut claims = Claims::new().unwrap();

        let add_claims_one = vec!["a", "b", "b"];
        let add_claims_two = 32;
        let add_claims_three = true;

        claims.add_additional("one", add_claims_one).unwrap();
        claims.add_additional("two", add_claims_two).unwrap();
        claims.add_additional("three", add_claims_three).unwrap();

        let as_string = claims.to_string().unwrap();
        let from_converted = Claims::from_string(&as_string).unwrap();
        assert_eq!(from_converted, claims);

        assert!(claims.contains_claim("one"));
        assert!(claims.contains_claim("two"));
        assert!(claims.contains_claim("three"));
    }

    #[test]
    fn test_token_no_expiration() {
        let mut claims = Claims::new().unwrap();
        let mut claims_validation = ClaimsValidationRules::new();

        claims.non_expiring();
        // Claims validation is not explicitly set to allow non-expiring, so we get error here
        // because claims is missing exp
        assert!(claims_validation.validate_claims(&claims).is_err());
        claims_validation.allow_non_expiring();
        assert!(claims_validation.validate_claims(&claims).is_ok());
    }

    #[test]
    fn test_token_missing_iat_nbf_exp() {
        let claims_validation = ClaimsValidationRules::new();

        // Default validation rules validate these times but error if they're missing
        let mut claims = Claims::new().unwrap();
        claims.list_of.remove("iat");
        assert!(claims_validation.validate_claims(&claims).is_err());

        let mut claims = Claims::new().unwrap();
        claims.list_of.remove("nbf");
        assert!(claims_validation.validate_claims(&claims).is_err());

        let mut claims = Claims::new().unwrap();
        claims.list_of.remove("exp");
        assert!(claims_validation.validate_claims(&claims).is_err());
    }

    #[test]
    fn test_custom_expiration_duration() {
        // Duration of 3 hours instead of 1.
        let duration = core::time::Duration::new(10800, 0);
        let mut claims = Claims::new_expires_in(&duration).unwrap();

        let claims_validation = ClaimsValidationRules::new();
        assert!(claims_validation.validate_claims(&claims).is_ok());

        claims
            .list_of
            .insert("exp".to_string(), "2019-01-01T00:00:00+00:00".into())
            .unwrap();
        // Expired
        assert_eq!(
            claims_validation.validate_claims(&claims).unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::Exp)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde() {
        let mut input = Claims::new().unwrap();
        input.issued_at("2020-01-01T00:00:00Z").unwrap();
        input.not_before("2020-01-02T00:00:00Z").unwrap();
        input.expiration("2020-01-03T00:00:00Z").unwrap();

        let json = serde_json::to_string(&input).unwrap();
        // it would be nice to compare full JSON, but the field order is not certain
        assert!(json.contains("\"iat\":\"2020-01-01T00:00:00Z\""));
        assert!(json.contains("\"nbf\":\"2020-01-02T00:00:00Z\""));
        assert!(json.contains("\"exp\":\"2020-01-03T00:00:00Z\""));

        let output: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(output, input);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_claims_from_string() {
        let mut claims = Claims::new().unwrap();

        // Fail to parse a registered claim that isn't a string
        claims
            .list_of
            .insert("nbf".into(), Value::Bool(false))
            .unwrap();
        let claimsstring = serde_json::to_string(&claims).unwrap();
        assert_eq!(
            Claims::from_string(&claimsstring).unwrap_err(),
            Error::InvalidClaim
        );
    }

    #[test]
    fn test_error_validation_if_registered_nostr() {
        let claims = Claims::new().unwrap();
        let claims_validation = ClaimsValidationRules::new();
        assert!(claims_validation.validate_claims(&claims).is_ok());

        let mut claims_nostr_exp = claims.clone();
        let mut claims_nostr_iat = claims.clone();
        let mut claims_nostr_nbf = claims.clone();

        // Check that expiry still is validated.
        claims_nostr_exp
            .list_of
            .insert("exp".to_string(), Value::Bool(false))
            .unwrap();
        assert_eq!(
            claims_validation
                .validate_claims(&claims_nostr_exp)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoStrExp)
        );

        claims_nostr_iat
            .list_of
            .insert("iat".to_string(), Value::Bool(false))
            .unwrap();
        assert_eq!(
            claims_validation
                .validate_claims(&claims_nostr_iat)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoStrIat)
        );

        claims_nostr_nbf
            .list_of
            .insert("nbf".to_string(), Value::Bool(false))
            .unwrap();
        assert_eq!(
            claims_validation
                .validate_claims(&claims_nostr_nbf)
                .unwrap_err(),
            Error::ClaimValidation(ClaimValidationError::NoStrNbf)
        );
    }
}
