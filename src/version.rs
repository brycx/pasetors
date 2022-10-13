use crate::errors::Error;

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
        /// Header for a public token for this version.
        const PUBLIC_HEADER: &'static str;
        /// Header for a local token for this version.
        const LOCAL_HEADER: &'static str;
        /// Size of a PASERK ID.
        #[cfg(feature = "paserk")]
        const PASERK_ID: usize;

        /// Validate bytes for a `local` key of a given version.
        fn validate_local_key(key_bytes: &[u8]) -> Result<(), Error>;
        /// Validate bytes for a secret `public` key of a given version.
        fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error>;
        /// Validate bytes for a public `local` key of a given version.
        fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error>;
    }
}
