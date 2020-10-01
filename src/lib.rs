//!
//!
//!
//!

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

mod errors;
mod pae;

/// PASETO version 2 tokens.
pub mod version2;

/// Errors for token operations.
pub use errors::Errors;
