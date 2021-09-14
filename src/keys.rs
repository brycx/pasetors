use crate::errors::Errors;
use alloc::vec::Vec;

// TODO!: Missing protections for the secret types.

#[derive(Debug, PartialEq)]
/// Versions associated with a key, used in PASETO.
pub enum Version {
    V2,
    V4,
}

const V2_KEYSIZE: usize = 32;
const V4_KEYSIZE: usize = V2_KEYSIZE;

/// A symmetric key used for `.local` tokens.
pub struct SymmetricKey {
    bytes: Vec<u8>,
    pub(crate) version: Version,
}

impl SymmetricKey {
    /// Randomly generate a `SymmetricKey` for a `version`.
    pub fn gen(version: Version) -> Result<Self, Errors> {
        if version == Version::V2 || version == Version::V4 {
            let mut rng_bytes = vec![0u8; V4_KEYSIZE];
            getrandom::getrandom(&mut rng_bytes)?;

            return Ok(Self {
                bytes: rng_bytes,
                version,
            });
        }

        return Err(Errors::KeyError);
    }

    /// Create a `SymmetricKey` from `bytes`, to be used with `version`.
    pub fn from(bytes: &[u8], version: Version) -> Result<Self, Errors> {
        if version == Version::V2 || version == Version::V4 {
            if bytes.len() != V4_KEYSIZE {
                return Err(Errors::KeyError);
            }

            return Ok(Self {
                bytes: bytes.to_vec(),
                version,
            });
        }

        return Err(Errors::KeyError);
    }

    /// Return this as a byte-slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// An asymmetric secret key used for `.public` tokens.
pub struct AsymmetricSecretKey {
    bytes: Vec<u8>,
    pub(crate) version: Version,
}

impl AsymmetricSecretKey {
    /// Create a `AsymmetricSecretKey` from `bytes`, to be used with `version`.
    pub fn from(bytes: &[u8], version: Version) -> Result<Self, Errors> {
        if version == Version::V2 || version == Version::V4 {
            if bytes.len() != V4_KEYSIZE {
                return Err(Errors::KeyError);
            }

            return Ok(Self {
                bytes: bytes.to_vec(),
                version,
            });
        }

        return Err(Errors::KeyError);
    }

    /// Return this as a byte-slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// An asymmetric public key used for `.public` tokens.
pub struct AsymmetricPublicKey {
    bytes: Vec<u8>,
    pub(crate) version: Version,
}

impl AsymmetricPublicKey {
    /// Create a `AsymmetricPublicKey` from `bytes`, to be used with `version`.
    pub fn from(bytes: &[u8], version: Version) -> Result<Self, Errors> {
        if version == Version::V2 || version == Version::V4 {
            if bytes.len() != V4_KEYSIZE {
                return Err(Errors::KeyError);
            }

            return Ok(Self {
                bytes: bytes.to_vec(),
                version,
            });
        }

        return Err(Errors::KeyError);
    }

    /// Return this as a byte-slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
