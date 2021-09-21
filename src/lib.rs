//! # Creating and verifying public tokens
//! ```rust
//! use pasetors::claims::{Claims, ClaimsValidationRules};
//! use pasetors::keys::{AsymmetricSecretKey, AsymmetricPublicKey, Version};
//! use pasetors::public;
//! use ed25519_dalek::Keypair;
//!
//! // Setup the default claims, which include `iat` and `nbf` as the current time and `exp` of one hour.
//! // Add a custom `data` claim as well.
//! let mut claims = Claims::new()?;
//! claims.add_additional("data", "A public, signed message")?;
//!
//! // Generate the keys and sign the claims.
//! let mut csprng = rand::rngs::OsRng{};
//! let keypair: Keypair = Keypair::generate(&mut csprng);
//! let sk = AsymmetricSecretKey::from(&keypair.secret.to_bytes(), Version::V4)?;
//! let pk = AsymmetricPublicKey::from(&keypair.public.to_bytes(), Version::V4)?;
//! let pub_token = public::sign(&sk, &pk, &claims, Some(b"footer"), Some(b"implicit assertion"))?;
//!
//! // Decide how we want to validate the claims after verifying the token itself.
//! // The default verifies the `nbf`, `iat` and `exp` claims. `nbf` and `iat` are always
//! // expected to be present.
//! let validation_rules = ClaimsValidationRules::new();
//! let claims_from = public::verify(&pk, &pub_token, &validation_rules, Some(b"footer"), Some(b"implicit assertion"))?;
//! assert_eq!(claims, claims_from);
//!
//! println!("{:?}", claims.get_claim("data"));
//! println!("{:?}", claims.get_claim("iat"));
//!
//! # Ok::<(), pasetors::errors::Errors>(())
//! ```

//! # Creating and verifying local tokens
//! ```rust
//! use pasetors::claims::{Claims, ClaimsValidationRules};
//! use pasetors::keys::{SymmetricKey, Version};
//! use pasetors::local;
//!
//! // Setup the default claims, which include `iat` and `nbf` as the current time and `exp` of one hour.
//! // Add a custom `data` claim as well.
//! let mut claims = Claims::new()?;
//! claims.add_additional("data", "A public, signed message")?;
//!
//! // Generate the keys and encrypt the claims.
//! let sk = SymmetricKey::gen(Version::V4)?;
//! let token = local::encrypt(&sk, &claims, Some(b"footer"), Some(b"implicit assertion"))?;
//!
//! // Decide how we want to validate the claims after verifying the token itself.
//! // The default verifies the `nbf`, `iat` and `exp` claims. `nbf` and `iat` are always
//! // expected to be present.
//! let validation_rules = ClaimsValidationRules::new();
//! let claims_from = local::decrypt(&sk, &token, &validation_rules, Some(b"footer"), Some(b"implicit assertion"))?;
//! assert_eq!(claims, claims_from);
//!
//! println!("{:?}", claims.get_claim("data"));
//! println!("{:?}", claims.get_claim("iat"));
//!
//! # Ok::<(), pasetors::errors::Errors>(())
//! ```

//! # Additional claims and their validation
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
//! # Ok::<(), pasetors::errors::Errors>(())
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
#![doc(html_root_url = "https://docs.rs/pasetors/0.2.0")]

#[macro_use]
extern crate alloc;

mod pae;

/// Errors for token operations.
pub mod errors;

mod common;

/// Claims for tokens and validation thereof.
pub mod claims;
/// Keys used for PASETO tokens.
pub mod keys;
/// PASETO version 2 tokens.
pub mod version2;
/// PASETO version 4 tokens.
pub mod version4;

/// PASETO public tokens using `Claims`.
pub mod public {
    use crate::claims::{Claims, ClaimsValidationRules};
    use crate::errors::Errors;
    use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey};

    /// Create a public token using the latest PASETO version (v4).
    pub fn sign(
        secret_key: &AsymmetricSecretKey,
        public_key: &AsymmetricPublicKey,
        message: &Claims,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Errors> {
        crate::version4::PublicToken::sign(
            secret_key,
            public_key,
            message.to_string().unwrap().as_bytes(),
            footer,
            implicit_assert,
        )
    }

    /// Verify a public token using the latest PASETO version (v4). If verification passes, validate the claims according to the
    /// `validation_rules`.
    pub fn verify(
        public_key: &AsymmetricPublicKey,
        token: &str,
        validation_rules: &ClaimsValidationRules,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<Claims, Errors> {
        crate::version4::PublicToken::verify(public_key, token, footer, implicit_assert)?;

        let parts_split = token.split('.').collect::<Vec<&str>>();
        let token_raw = crate::common::decode_b64(parts_split[2])?;

        let claims =
            Claims::from_bytes(&token_raw[..token_raw.len() - ed25519_dalek::SIGNATURE_LENGTH])?;
        validation_rules.validate_claims(&claims)?;

        Ok(claims)
    }
}

/// PASETO local tokens using `Claims`.
pub mod local {
    use crate::claims::{Claims, ClaimsValidationRules};
    use crate::errors::Errors;
    use crate::keys::SymmetricKey;

    /// Create a local token using the latest PASETO version (v4).
    pub fn encrypt(
        secret_key: &SymmetricKey,
        message: &Claims,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Errors> {
        crate::version4::LocalToken::encrypt(
            secret_key,
            message.to_string().unwrap().as_bytes(),
            footer,
            implicit_assert,
        )
    }

    /// Verify a local token using the latest PASETO version (v4). If verification passes, validate the claims according to the
    /// `validation_rules`.
    pub fn decrypt(
        secret_key: &SymmetricKey,
        token: &str,
        validation_rules: &ClaimsValidationRules,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<Claims, Errors> {
        let raw_payload =
            crate::version4::LocalToken::decrypt(secret_key, token, footer, implicit_assert)?;
        let claims = Claims::from_bytes(&raw_payload)?;
        validation_rules.validate_claims(&claims)?;

        Ok(claims)
    }
}
