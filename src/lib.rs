//! # Usage:
//! ```rust
//! use pasetors::version4::*;
//! use pasetors::keys::*;
//! use ed25519_dalek::Keypair;
//!
//! let mut csprng = rand::rngs::OsRng{};
//!
//! // Create and verify a public token
//! let keypair: Keypair = Keypair::generate(&mut csprng);
//! let sk = AsymmetricSecretKey::from(&keypair.secret.to_bytes(), Version::V4)?;
//! let pk = AsymmetricPublicKey::from(&keypair.public.to_bytes(), Version::V4)?;
//! let pub_token = PublicToken::sign(&sk, &pk, b"Message to sign", Some(b"footer"), Some(b"implicit assertion"))?;
//! assert!(PublicToken::verify(&pk, &pub_token, Some(b"footer"), Some(b"implicit assertion")).is_ok());
//!
//! // Create and verify a local token
//! let sk = SymmetricKey::gen(Version::V4)?;
//!
//! let local_token = LocalToken::encrypt(&sk, b"Message to encrypt and authenticate", Some(b"footer"), Some(b"implicit assertion"))?;
//! assert!(LocalToken::decrypt(&sk, &local_token, Some(b"footer"), Some(b"implicit assertion")).is_ok());
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

        let claims = Claims::from_string(token)?;
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
