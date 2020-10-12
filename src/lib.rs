//! # Usage example:
//! ```rust
//! use pasetors::version2::*;
//! use rand::rngs::OsRng;
//!
//! // WARNING: Only for testing - never hard-code secrets!
//! let ed25519_secret_key = [
//!    180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125,
//!    159, 133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116,
//! ];
//! let ed25519_public_key = [
//!    30, 185, 219, 187, 188, 4, 124, 3, 253, 112, 96, 78, 0, 113, 240, 152, 126, 22, 178, 139,
//!    117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177, 162,
//! ];
//! let shared_secret = [
//!    180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125,
//!    159, 133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116,
//! ];
//!
//! // Create and verify a public token
//! let pub_token = PublicToken::sign(&ed25519_secret_key, &ed25519_public_key, b"Message to sign", Some(b"footer"))?;
//! assert!(PublicToken::verify(&ed25519_public_key, &pub_token, Some(b"footer")).is_ok());
//!
//! // Create and verify a local token
//! let mut csprng = OsRng{};
//!
//! let local_token = LocalToken::encrypt(&mut csprng, &shared_secret, b"Message to encrypt and authenticate", Some(b"footer"))?;
//! assert!(LocalToken::decrypt(&shared_secret, &local_token, Some(b"footer")).is_ok());
//!
//! # Ok::<(), pasetors::errors::Errors>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::mem_forget)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_qualifications,
    overflowing_literals
)]
#![doc(html_root_url = "https://docs.rs/pasetors/0.1.0")]

#[macro_use]
extern crate alloc;

mod pae;

/// Errors for token operations.
pub mod errors;

/// PASETO version 2 tokens.
pub mod version2;
