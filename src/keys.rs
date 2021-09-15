use crate::errors::Errors;
use alloc::vec::Vec;

// TODO!: Missing protections for the secret types.

#[derive(Debug, PartialEq, Copy, Clone)]
/// Versions associated with a key, used in PASETO.
pub enum Version {
    /// Keys for version 2.
    V2,
    /// Keys for version 4.
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

        Err(Errors::KeyError)
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

        Err(Errors::KeyError)
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
            if bytes.len() != ed25519_dalek::SECRET_KEY_LENGTH {
                return Err(Errors::KeyError);
            }

            return Ok(Self {
                bytes: bytes.to_vec(),
                version,
            });
        }

        Err(Errors::KeyError)
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
            if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
                return Err(Errors::KeyError);
            }

            return Ok(Self {
                bytes: bytes.to_vec(),
                version,
            });
        }

        Err(Errors::KeyError)
    }

    /// Return this as a byte-slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_gen() {
        let randomv2 = SymmetricKey::gen(Version::V2).unwrap();
        let randomv4 = SymmetricKey::gen(Version::V4).unwrap();

        assert_ne!(randomv2.as_bytes(), &[0u8; 32]);
        assert_ne!(randomv4.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_invalid_sizes() {
        // Version 2
        assert!(AsymmetricSecretKey::from(&[0u8; 31], Version::V2).is_err());
        assert!(AsymmetricSecretKey::from(&[0u8; 32], Version::V2).is_ok());
        assert!(AsymmetricSecretKey::from(&[0u8; 33], Version::V2).is_err());

        assert!(AsymmetricPublicKey::from(&[0u8; 31], Version::V2).is_err());
        assert!(AsymmetricPublicKey::from(&[0u8; 32], Version::V2).is_ok());
        assert!(AsymmetricPublicKey::from(&[0u8; 33], Version::V2).is_err());

        assert!(SymmetricKey::from(&[0u8; 31], Version::V2).is_err());
        assert!(SymmetricKey::from(&[0u8; 32], Version::V2).is_ok());
        assert!(SymmetricKey::from(&[0u8; 33], Version::V2).is_err());

        // Version 4
        assert!(AsymmetricSecretKey::from(&[0u8; 31], Version::V4).is_err());
        assert!(AsymmetricSecretKey::from(&[0u8; 32], Version::V4).is_ok());
        assert!(AsymmetricSecretKey::from(&[0u8; 33], Version::V4).is_err());

        assert!(AsymmetricPublicKey::from(&[0u8; 31], Version::V4).is_err());
        assert!(AsymmetricPublicKey::from(&[0u8; 32], Version::V4).is_ok());
        assert!(AsymmetricPublicKey::from(&[0u8; 33], Version::V4).is_err());

        assert!(SymmetricKey::from(&[0u8; 31], Version::V4).is_err());
        assert!(SymmetricKey::from(&[0u8; 32], Version::V4).is_ok());
        assert!(SymmetricKey::from(&[0u8; 33], Version::V4).is_err());
    }
}
