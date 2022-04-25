use crate::errors::Error;
use private::Version;

pub(crate) mod private {
    use super::Error;

    // Inside private module to prevent users from implementing this themself.

    /// A given version must implement validation logic in terms of both itself and the kind of key.
    pub trait Version {
        /// Size for a `local` key.
        const LOCAL_KEY: usize;
        /// Size for a secret `public` key.
        const SECRET_KEY: usize;
        /// Size for a public `public` key.
        const PUBLIC_KEY: usize;
        /// Size of the signature for a public token.
        const PUBLIC_SIG: usize;
        /// Size of the nonce for a local token.
        const LOCAL_NONCE: usize;
        /// Size of the authentication tag for a local token.
        const LOCAL_TAG: usize;

        /// Validate bytes for a `local` key of a given version.
        fn validate_local_key(key_bytes: &[u8]) -> Result<(), Error>;
        /// Validate bytes for a secret `public` key of a given version.
        fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error>;
        /// Validate bytes for a public `local` key of a given version.
        fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error>;
        /// Get the header of a public token for this version.
        fn public_header() -> &'static str;
        /// Get the header of a local token for this version.
        fn local_header() -> &'static str;
    }
}

#[derive(Debug, PartialEq, Clone)]
/// Version 2 of the PASETO spec.
pub struct V2;

#[derive(Debug, PartialEq, Clone)]
/// Version 3 of the PASETO spec.
pub struct V3;

#[derive(Debug, PartialEq, Clone)]
/// Version 4 of the PASETO spec.
pub struct V4;

impl Version for V2 {
    const LOCAL_KEY: usize = 32;
    const SECRET_KEY: usize = 32;
    const PUBLIC_KEY: usize = 32;
    const PUBLIC_SIG: usize = 64;
    const LOCAL_NONCE: usize = 24;
    const LOCAL_TAG: usize = 16;

    fn validate_local_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::LOCAL_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error> {
        Self::validate_local_key(key_bytes)
    }

    fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error> {
        Self::validate_secret_key(key_bytes)
    }

    fn public_header() -> &'static str {
        "v2.public."
    }

    fn local_header() -> &'static str {
        "v2.local."
    }
}

impl Version for V3 {
    const LOCAL_KEY: usize = 32;
    const SECRET_KEY: usize = 48;
    const PUBLIC_KEY: usize = 49;
    const PUBLIC_SIG: usize = 96;
    const LOCAL_NONCE: usize = 32;
    const LOCAL_TAG: usize = 48;

    fn validate_local_key(_key_bytes: &[u8]) -> Result<(), Error> {
        unimplemented!();
    }

    fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::SECRET_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::PUBLIC_KEY {
            return Err(Error::Key);
        }
        if key_bytes[0] != 0x02 && key_bytes[0] != 0x03 {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn public_header() -> &'static str {
        "v3.public."
    }

    fn local_header() -> &'static str {
        "v3.local."
    }
}

impl Version for V4 {
    const LOCAL_KEY: usize = V2::LOCAL_KEY;
    const SECRET_KEY: usize = V2::SECRET_KEY;
    const PUBLIC_KEY: usize = V2::PUBLIC_KEY;
    const PUBLIC_SIG: usize = V2::PUBLIC_SIG;
    const LOCAL_NONCE: usize = 32;
    const LOCAL_TAG: usize = 32;

    fn validate_local_key(key_bytes: &[u8]) -> Result<(), Error> {
        V2::validate_local_key(key_bytes)
    }

    fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error> {
        V2::validate_secret_key(key_bytes)
    }

    fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error> {
        V2::validate_public_key(key_bytes)
    }

    fn public_header() -> &'static str {
        "v4.public."
    }

    fn local_header() -> &'static str {
        "v4.local."
    }
}
