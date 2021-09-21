use crate::errors::Errors;
use chrono::prelude::*;
use chrono::Duration;
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
/// A collection of claims that are passed as payload for a PASETO token.
pub struct Claims {
    list_of: HashMap<String, String>,
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
    pub fn new() -> Result<Self, Errors> {
        let iat = Utc::now();
        let nbf = iat;
        let exp = match iat.checked_add_signed(Duration::hours(1)) {
            Some(value) => value,
            None => return Err(Errors::InvalidClaimError),
        };

        let mut claims = Self {
            list_of: HashMap::new(),
        };

        claims.issued_at(&iat.to_string())?;
        claims.not_before(&nbf.to_string())?;
        claims.expiration(&exp.to_string())?;

        Ok(claims)
    }

    /// Add additional claims. If `claim` already exists, it is replaced with the new.
    ///
    /// Errors:
    /// - `claim` is a reserved claim (see [`Self::REGISTERED_CLAIMS`])
    pub fn add_additional(&mut self, claim: &str, value: &str) -> Result<(), Errors> {
        if !Self::REGISTERED_CLAIMS.contains(&claim) {
            self.list_of.insert(claim.into(), value.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }

    /// Checks whether a specific claim has been added to the list.
    ///
    /// E.g `contains_claim("iss") == true` if `iss` has been added before.
    pub fn contains_claim(&self, claim: &str) -> bool {
        self.list_of.contains_key(claim)
    }

    /// Set the `iss` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `iss` is empty
    pub fn issuer(&mut self, iss: &str) -> Result<(), Errors> {
        if !iss.is_empty() {
            self.list_of.insert("iss".into(), iss.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }

    /// Set the `sub` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `sub` is empty
    pub fn subject(&mut self, sub: &str) -> Result<(), Errors> {
        if !sub.is_empty() {
            self.list_of.insert("sub".into(), sub.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }

    /// Set the `aud` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `aud` is empty
    pub fn audience(&mut self, aud: &str) -> Result<(), Errors> {
        if !aud.is_empty() {
            self.list_of.insert("aud".into(), aud.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }

    /// Set the `exp` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `exp` is empty
    /// - `exp` cannot be parsed as a ISO 8601 compliant DateTime string.
    pub fn expiration(&mut self, exp: &str) -> Result<(), Errors> {
        if exp.parse::<DateTime<Utc>>().is_ok() {
            self.list_of.insert("exp".into(), exp.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }

    /// Set the `nbf` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `nbf` is empty
    /// - `nbf` cannot be parsed as a ISO 8601 compliant DateTime string.
    pub fn not_before(&mut self, nbf: &str) -> Result<(), Errors> {
        if nbf.parse::<DateTime<Utc>>().is_ok() {
            self.list_of.insert("nbf".into(), nbf.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }

    /// Set the `iat` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `iat` is empty
    /// - `iat` cannot be parsed as a ISO 8601 compliant DateTime string.
    pub fn issued_at(&mut self, iat: &str) -> Result<(), Errors> {
        if iat.parse::<DateTime<Utc>>().is_ok() {
            self.list_of.insert("iat".into(), iat.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }

    /// Set the `jti` claim. If it already exists, replace it with the new.
    ///
    /// Errors:
    /// - `jti` is empty
    pub fn token_identifier(&mut self, jti: &str) -> Result<(), Errors> {
        if !jti.is_empty() {
            self.list_of.insert("jti".into(), jti.into());
            Ok(())
        } else {
            Err(Errors::InvalidClaimError)
        }
    }
}

/// The validation rules that are used to validate a set of claims.
pub struct ClaimsValidationRules {
    // TODO: How to allow validating for non-expiring tokens.
    validate_currently_valid: bool,
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
            validate_issuer: None,
            validate_subject: None,
            validate_audience: None,
            validate_token_identifier: None,
        }
    }

    /// Set the `valid_issuer` the claims should be validated against.
    pub fn validate_issuer(&mut self, valid_issuer: &str) {
        self.validate_issuer = Some(valid_issuer.to_string());
    }

    /// Set the `valid_subject` the claims should be validated against.
    pub fn validate_subject(&mut self, valid_subject: &str) {
        self.validate_subject = Some(valid_subject.to_string());
    }

    /// Set the `valid_audience` the claims should be validated against.
    pub fn validate_audience(&mut self, valid_audience: &str) {
        self.validate_audience = Some(valid_audience.to_string());
    }

    /// Set the `valid_token_identifier` the claims should be validated against.
    pub fn validate_token_identifier(&mut self, valid_token_identifier: &str) {
        self.validate_token_identifier = Some(valid_token_identifier.to_string());
    }

    /// Validate the set of `claims` against the currently defined validation rules.
    pub fn validate_claims(&self, claims: &Claims) -> Result<(), Errors> {
        if self.validate_currently_valid {
            match (
                claims.list_of.get("iat"),
                claims.list_of.get("nbf"),
                claims.list_of.get("exp"),
            ) {
                (Some(iat), Some(nbf), Some(exp)) => {
                    let iat = iat
                        .parse::<DateTime<Utc>>()
                        .map_err(|_| Errors::ClaimValidationError)?;
                    let nbf = nbf
                        .parse::<DateTime<Utc>>()
                        .map_err(|_| Errors::ClaimValidationError)?;
                    let exp = exp
                        .parse::<DateTime<Utc>>()
                        .map_err(|_| Errors::ClaimValidationError)?;
                    let current_time = Utc::now();

                    if current_time > exp || current_time < nbf || current_time < iat {
                        return Err(Errors::ClaimValidationError);
                    }
                }
                _ => return Err(Errors::ClaimValidationError),
            }
        }

        if let Some(expected_issuer) = &self.validate_issuer {
            if let Some(actual_issuer) = claims.list_of.get("iss") {
                if expected_issuer != actual_issuer {
                    return Err(Errors::ClaimValidationError);
                }
            } else {
                return Err(Errors::ClaimValidationError);
            }
        }

        if let Some(expected_subject) = &self.validate_subject {
            if let Some(actual_subject) = claims.list_of.get("sub") {
                if expected_subject != actual_subject {
                    return Err(Errors::ClaimValidationError);
                }
            } else {
                return Err(Errors::ClaimValidationError);
            }
        }

        if let Some(expected_audience) = &self.validate_audience {
            if let Some(actual_audience) = claims.list_of.get("aud") {
                if expected_audience != actual_audience {
                    return Err(Errors::ClaimValidationError);
                }
            } else {
                return Err(Errors::ClaimValidationError);
            }
        }

        if let Some(expected_token_identifier) = &self.validate_token_identifier {
            if let Some(actual_token_identifier) = claims.list_of.get("jti") {
                if expected_token_identifier != actual_token_identifier {
                    return Err(Errors::ClaimValidationError);
                }
            } else {
                return Err(Errors::ClaimValidationError);
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
    }

    #[test]
    fn test_contains_claim() {
        let mut claims = Claims::new().unwrap();

        // Default claims
        assert_eq!(claims.contains_claim("iat"), true);
        assert_eq!(claims.contains_claim("nbf"), true);
        assert_eq!(claims.contains_claim("exp"), true);

        assert_eq!(claims.contains_claim("iss"), false);
        claims.issuer("testIssuer").unwrap();
        assert_eq!(claims.contains_claim("iss"), true);

        assert_eq!(claims.contains_claim("aud"), false);
        claims.audience("testAudience").unwrap();
        assert_eq!(claims.contains_claim("aud"), true);
    }
}
