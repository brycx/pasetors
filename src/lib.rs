//! # Usage:
//! ```rust
//! use pasetors::version2::*;
//! use rand::RngCore;
//! use ed25519_dalek::Keypair;
//!
//! let mut csprng = rand::rngs::OsRng{};
//!
//! // Create and verify a public token
//! let keypair: Keypair = Keypair::generate(&mut csprng);
//! let pub_token = PublicToken::sign(&keypair.secret.to_bytes(), &keypair.public.to_bytes(), b"Message to sign", Some(b"footer"))?;
//! assert!(PublicToken::verify(&keypair.public.to_bytes(), &pub_token, Some(b"footer")).is_ok());
//!
//! // Create and verify a local token
//! let mut secret = [0u8; 32];
//! csprng.try_fill_bytes(&mut secret)?;
//!
//! let local_token = LocalToken::encrypt(&mut csprng, &secret, b"Message to encrypt and authenticate", Some(b"footer"))?;
//! assert!(LocalToken::decrypt(&secret, &local_token, Some(b"footer")).is_ok());
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
#![doc(html_root_url = "https://docs.rs/pasetors/0.1.1")]

#[macro_use]
extern crate alloc;

mod pae;

/// Errors for token operations.
pub mod errors;

/// PASETO version 2 tokens.
pub mod version2;
