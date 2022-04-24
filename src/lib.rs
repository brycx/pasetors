//! # Getting started
//! This library has two ways of working with tokens. The first is the [`local`] and [`public`] module,
//! which the below examples make use of. These use the latest version of PASETO for tokens,
//! along with [`claims::Claims`], to enable a straightforward way of defining common claims.
//! [`claims::ClaimsValidationRules`] lets you define validation rules, that are covered when using
//! the [`local`] and [`public`] module. Using these modules means that validation of registered
//! claims is handled automatically.
//!
//! If more control over the input is needed, and validation is handled manually, the [`version4`]/[`version2`]
//! module provide a lower-level interface, where payloads are be provided as byte-slices.
//!
//! NOTE: [`claims`], [`local`] and [`public`] modules are __only available with default-features enabled__.
//! ## Creating and verifying public tokens
//! ```rust
//! use pasetors::claims::{Claims, ClaimsValidationRules};
//! use pasetors::keys::{Generate, AsymmetricKeyPair, AsymmetricSecretKey, AsymmetricPublicKey};
//! use pasetors::{public, Public, V4};
//! use pasetors::token::{UntrustedToken, TrustedToken};
//! use core::convert::TryFrom;
//!
//! // Setup the default claims, which include `iat` and `nbf` as the current time and `exp` of one hour.
//! // Add a custom `data` claim as well.
//! let mut claims = Claims::new()?;
//! claims.add_additional("data", "A public, signed message")?;
//!
//! // Generate the keys and sign the claims.
//! let kp = AsymmetricKeyPair::<V4>::generate()?;
//! let pub_token = public::sign(&kp.secret, &kp.public, &claims, Some(b"footer"), Some(b"implicit assertion"))?;
//!
//! // Decide how we want to validate the claims after verifying the token itself.
//! // The default verifies the `nbf`, `iat` and `exp` claims. `nbf` and `iat` are always
//! // expected to be present.
//! // NOTE: Custom claims, defined through `add_additional()`, are not validated. This must be done
//! // manually.
//! let validation_rules = ClaimsValidationRules::new();
//! let untrusted_token = UntrustedToken::<Public, V4>::try_from(&pub_token)?;
//! let trusted_token = public::verify(&kp.public, &untrusted_token, &validation_rules, Some(b"footer"), Some(b"implicit assertion"))?;
//! assert_eq!(&claims, trusted_token.payload_claims().unwrap());
//!
//! let claims = trusted_token.payload_claims().unwrap();
//!
//! println!("{:?}", claims.get_claim("data"));
//! println!("{:?}", claims.get_claim("iat"));
//!
//! # Ok::<(), pasetors::errors::Error>(())
//! ```

//! ## Creating and verifying local tokens
//! ```rust
//! use pasetors::claims::{Claims, ClaimsValidationRules};
//! use pasetors::keys::{Generate, SymmetricKey};
//! use pasetors::{local, Local, V4};
//! use pasetors::token::UntrustedToken;
//! use core::convert::TryFrom;
//!
//! // Setup the default claims, which include `iat` and `nbf` as the current time and `exp` of one hour.
//! // Add a custom `data` claim as well.
//! let mut claims = Claims::new()?;
//! claims.add_additional("data", "A secret, encrypted message")?;
//!
//! // Generate the key and encrypt the claims.
//! let sk = SymmetricKey::<V4>::generate()?;
//! let token = local::encrypt(&sk, &claims, Some(b"footer"), Some(b"implicit assertion"))?;
//!
//! // Decide how we want to validate the claims after verifying the token itself.
//! // The default verifies the `nbf`, `iat` and `exp` claims. `nbf` and `iat` are always
//! // expected to be present.
//! // NOTE: Custom claims, defined through `add_additional()`, are not validated. This must be done
//! // manually.
//! let validation_rules = ClaimsValidationRules::new();
//! let untrusted_token = UntrustedToken::<Local, V4>::try_from(&token)?;
//! let trusted_token = local::decrypt(&sk, &untrusted_token, &validation_rules, Some(b"footer"), Some(b"implicit assertion"))?;
//! assert_eq!(&claims, trusted_token.payload_claims().unwrap());
//!
//! let claims = trusted_token.payload_claims().unwrap();
//!
//! println!("{:?}", claims.get_claim("data"));
//! println!("{:?}", claims.get_claim("iat"));
//!
//! # Ok::<(), pasetors::errors::Error>(())
//! ```

//! ## Additional claims and their validation
//!
//! ### Setting registered claims and how to validate them
//! ```rust
//! use pasetors::claims::{Claims, ClaimsValidationRules};
//!
//! // `iat`, `nbf` and `exp` have been set automatically, but could also be overridden.
//! let mut claims = Claims::new()?;
//! claims.issuer("paragonie.com")?;
//! claims.subject("test")?;
//! claims.audience("pie-hosted.com")?;
//! claims.expiration("2039-01-01T00:00:00+00:00")?;
//! claims.not_before("2038-04-01T00:00:00+00:00")?;
//! claims.issued_at("2038-03-17T00:00:00+00:00")?;
//! claims.token_identifier("87IFSGFgPNtQNNuw0AtuLttPYFfYwOkjhqdWcLoYQHvL")?;
//!
//! let mut validation_rules = ClaimsValidationRules::new();
//! validation_rules.validate_issuer_with("paragonie.com");
//! validation_rules.validate_subject_with("test");
//! validation_rules.validate_audience_with("pie-hosted.com");
//! validation_rules.validate_token_identifier_with("87IFSGFgPNtQNNuw0AtuLttPYFfYwOkjhqdWcLoYQHvL");
//!
//! // The token has been set to be issued in the future and not valid yet, so validation fails.
//! assert!(validation_rules.validate_claims(&claims).is_err());
//! # Ok::<(), pasetors::errors::Error>(())
//! ```
//! ### Non-expiring tokens
//! ```rust
//! use pasetors::claims::{Claims, ClaimsValidationRules};
//!
//! // Non-expiring tokens
//! let mut claims = Claims::new()?;
//! claims.add_additional("data", "A public, signed message")?;
//! claims.non_expiring();
//! // Now claims can be validated as non-expiring when we define the validation rule as:
//! let mut validation_rules = ClaimsValidationRules::new();
//! validation_rules.allow_non_expiring();
//!
//! # Ok::<(), pasetors::errors::Error>(())
//! ```

//! ## PASERK serialization
//! ```rust
//! use pasetors::paserk::FormatAsPaserk;
//! use pasetors::keys::{Generate, SymmetricKey};
//! use pasetors::V4;
//! use core::convert::TryFrom;
//!
//! // Generate the key and serialize to and from PASERK.
//! let sk = SymmetricKey::<V4>::generate()?;
//! let mut paserk = String::new();
//! sk.fmt(&mut paserk).unwrap();
//! let sk = SymmetricKey::<V4>::try_from(paserk)?;
//!
//! # Ok::<(), pasetors::errors::Error>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::mem_forget)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_qualifications,
    overflowing_literals
)]
#![doc(html_root_url = "https://docs.rs/pasetors/0.4.2")]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
extern crate alloc;

mod pae;

/// Errors for token operations.
pub mod errors;

mod common;

#[cfg(feature = "std")]
/// Claims for tokens and validation thereof.
pub mod claims;

#[cfg(feature = "std")]
/// Footer for tokens and validation thereof.
pub mod footer;

/// Keys used for PASETO tokens.
pub mod keys;

#[cfg(feature = "paserk")]
/// PASERK key-wrapping and serialization.
pub mod paserk;

#[cfg(feature = "v2")]
/// PASETO version 2 tokens.
pub mod version2;

#[cfg(feature = "v3")]
/// PASETO version 3 tokens.
pub mod version3;

#[cfg(feature = "v4")]
/// PASETO version 4 tokens.
pub mod version4;

/// Types for handling tokens.
pub mod token;

mod version;

/// Versions of the PASETO spec implemented.
pub use version::{V2, V3, V4};

/// Public and local tokens.
pub use token::{Local, Public};

#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "v4"))))]
#[cfg(all(feature = "std", feature = "v4"))]
/// PASETO public tokens with [`version4`], using [`claims::Claims`].
pub mod public {
    use super::*;
    use crate::claims::{Claims, ClaimsValidationRules};
    use crate::errors::Error;
    use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
    use crate::token::{TrustedToken, UntrustedToken};

    /// Create a public token using the latest PASETO version (v4).
    pub fn sign(
        secret_key: &AsymmetricSecretKey<V4>,
        public_key: &AsymmetricPublicKey<V4>,
        message: &Claims,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        crate::version4::PublicToken::sign(
            secret_key,
            public_key,
            message.to_string()?.as_bytes(),
            footer,
            implicit_assert,
        )
    }

    /// Verify a public token using the latest PASETO version (v4). If verification passes,
    /// validate the claims according to the `validation_rules`.
    pub fn verify(
        public_key: &AsymmetricPublicKey<V4>,
        token: &UntrustedToken<Public, V4>,
        validation_rules: &ClaimsValidationRules,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        let mut trusted_token =
            crate::version4::PublicToken::verify(public_key, token, footer, implicit_assert)?;

        let claims = Claims::from_string(trusted_token.payload())?;
        validation_rules.validate_claims(&claims)?;
        trusted_token.set_payload_claims(claims);

        Ok(trusted_token)
    }
}

#[cfg_attr(docsrs, doc(cfg(all(feature = "std", feature = "v4"))))]
#[cfg(all(feature = "std", feature = "v4"))]
/// PASETO local tokens with [`version4`], using [`claims::Claims`].
pub mod local {
    use super::*;
    use crate::claims::{Claims, ClaimsValidationRules};
    use crate::errors::Error;
    use crate::keys::SymmetricKey;
    use crate::token::{TrustedToken, UntrustedToken};

    /// Create a local token using the latest PASETO version (v4).
    pub fn encrypt(
        secret_key: &SymmetricKey<V4>,
        message: &Claims,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        crate::version4::LocalToken::encrypt(
            secret_key,
            message.to_string()?.as_bytes(),
            footer,
            implicit_assert,
        )
    }

    /// Verify a local token using the latest PASETO version (v4). If verification passes,
    /// validate the claims according to the `validation_rules`.
    pub fn decrypt(
        secret_key: &SymmetricKey<V4>,
        token: &UntrustedToken<Local, V4>,
        validation_rules: &ClaimsValidationRules,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        let mut trusted_token =
            crate::version4::LocalToken::decrypt(secret_key, token, footer, implicit_assert)?;

        let claims = Claims::from_string(trusted_token.payload())?;
        validation_rules.validate_claims(&claims)?;
        trusted_token.set_payload_claims(claims);

        Ok(trusted_token)
    }
}
