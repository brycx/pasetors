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
