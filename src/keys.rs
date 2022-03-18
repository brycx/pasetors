use crate::errors::Error;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;
use private::Version;

pub(crate) mod private {
    use super::Error;

    // Inside private module to prevent users from implementing this themself.

    /// A given version must implement validation logic in terms of both itself and the kind of key.
    pub trait Version {
        /// Size for a `local` key.
        const LOCAL: usize;
        /// Size for a secret `public` key.
        const SECRET: usize;
        /// Size for a public `public` key.
        const PUBLIC: usize;

        /// Validate bytes for a `local` key of a given version.
        fn validate_local(key_bytes: &[u8]) -> Result<(), Error>;
        /// Validate bytes for a secret `public` key of a given version.
        fn validate_secret(key_bytes: &[u8]) -> Result<(), Error>;
        /// Validate bytes for a public `local` key of a given version.
        fn validate_public(key_bytes: &[u8]) -> Result<(), Error>;
    }
}

/// Version 2 of the PASETO spec.
pub struct V2;

/// Version 3 of the PASETO spec.
pub struct V3;

/// Version 4 of the PASETO spec.
pub struct V4;

impl Version for V2 {
    const LOCAL: usize = 32;
    const SECRET: usize = 32;
    const PUBLIC: usize = 32;

    fn validate_local(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::LOCAL {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_secret(key_bytes: &[u8]) -> Result<(), Error> {
        Self::validate_local(key_bytes)
    }

    fn validate_public(key_bytes: &[u8]) -> Result<(), Error> {
        Self::validate_secret(key_bytes)
    }
}

impl Version for V3 {
    const LOCAL: usize = 32;
    const SECRET: usize = 48;
    const PUBLIC: usize = 49;

    fn validate_local(_key_bytes: &[u8]) -> Result<(), Error> {
        unimplemented!();
    }

    fn validate_secret(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::SECRET {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_public(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::PUBLIC {
            return Err(Error::Key);
        }
        if key_bytes[0] != 0x02 && key_bytes[0] != 0x03 {
            return Err(Error::Key);
        }

        Ok(())
    }
}

impl Version for V4 {
    const LOCAL: usize = V2::LOCAL;
    const SECRET: usize = V2::SECRET;
    const PUBLIC: usize = V2::PUBLIC;

    fn validate_local(key_bytes: &[u8]) -> Result<(), Error> {
        V2::validate_local(key_bytes)
    }

    fn validate_secret(key_bytes: &[u8]) -> Result<(), Error> {
        V2::validate_secret(key_bytes)
    }

    fn validate_public(key_bytes: &[u8]) -> Result<(), Error> {
        V2::validate_public(key_bytes)
    }
}

/// A symmetric key used for `.local` tokens, given a version `V`.
pub struct SymmetricKey<V> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) phantom: PhantomData<V>,
}

impl<V: Version> SymmetricKey<V> {
    /// Create a `SymmetricKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Error> {
        V::validate_local(bytes)?;

        Ok(Self {
            bytes: bytes.to_vec(),
            phantom: PhantomData,
        })
    }

    /// Return this as a byte-slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Randomly generate a `SymmetricKey`.
    pub fn gen() -> Result<Self, Error> {
        let mut rng_bytes = vec![0u8; V::LOCAL];
        // We add this on all-zero bytes, to "propagate" the `unimplemented!()` for `v3.local`.
        V::validate_local(&rng_bytes)?;
        getrandom::getrandom(&mut rng_bytes)?;

        Ok(Self {
            bytes: rng_bytes,
            phantom: PhantomData,
        })
    }
}

impl<V> Drop for SymmetricKey<V> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.iter_mut().zeroize();
    }
}

impl<V> Debug for SymmetricKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SymmetricKey {{***OMITTED***}}")
    }
}

/// An asymmetric secret key used for `.public` tokens, given a version `V`.
pub struct AsymmetricSecretKey<V> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) phantom: PhantomData<V>,
}

impl<V: Version> AsymmetricSecretKey<V> {
    /// Create a `AsymmetricSecretKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Error> {
        V::validate_secret(bytes)?;

        Ok(Self {
            bytes: bytes.to_vec(),
            phantom: PhantomData,
        })
    }

    /// Return this as a byte-slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<V> Drop for AsymmetricSecretKey<V> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.iter_mut().zeroize();
    }
}

impl<V> Debug for AsymmetricSecretKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AsymmetricSecretKey {{***OMITTED***}}")
    }
}

#[derive(Debug)]
/// An asymmetric public key used for `.public` tokens, given a version `V`.
pub struct AsymmetricPublicKey<V> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) phantom: PhantomData<V>,
}

impl<V: Version> AsymmetricPublicKey<V> {
    /// Create a `AsymmetricPublicKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Error> {
        V::validate_public(bytes)?;

        Ok(Self {
            bytes: bytes.to_vec(),
            phantom: PhantomData,
        })
    }

    /// Return this as a byte-slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Debug)]
/// A keypair of an [`AsymmetricSecretKey`] and its corresponding `AsymmetricPublicKey`.
pub struct AsymmetricKeyPair<V> {
    /// The [`AsymmetricSecretKey`].
    pub public: AsymmetricPublicKey<V>,
    /// The [`AsymmetricPublicKey`].
    pub secret: AsymmetricSecretKey<V>,
}

#[cfg(test)]
#[cfg(feature = "std")]
// NOTE: Only intended for V2/V4 testing purposes.
impl<V: Version> AsymmetricKeyPair<V> {
    pub(crate) fn from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != V2::SECRET + V2::PUBLIC {
            return Err(Error::PaserkParsing);
        }

        Ok(Self {
            secret: AsymmetricSecretKey::from(&bytes[..V2::SECRET])?,
            public: AsymmetricPublicKey::from(&bytes[V2::SECRET..])?,
        })
    }

    pub(crate) fn as_bytes<'a>(&self) -> [u8; 64] {
        let mut buf = [0u8; V2::SECRET + V2::PUBLIC];
        buf[..V2::SECRET].copy_from_slice(self.secret.as_bytes());
        buf[V2::SECRET..].copy_from_slice(self.public.as_bytes());

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_gen() {
        let randomv2 = SymmetricKey::<V2>::gen().unwrap();
        let randomv4 = SymmetricKey::<V4>::gen().unwrap();

        assert_ne!(randomv2.as_bytes(), &[0u8; 32]);
        assert_ne!(randomv4.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_invalid_sizes() {
        // Version 2
        assert!(AsymmetricSecretKey::<V2>::from(&[0u8; 31]).is_err());
        assert!(AsymmetricSecretKey::<V2>::from(&[0u8; 32]).is_ok());
        assert!(AsymmetricSecretKey::<V2>::from(&[0u8; 33]).is_err());

        assert!(AsymmetricPublicKey::<V2>::from(&[0u8; 31]).is_err());
        assert!(AsymmetricPublicKey::<V2>::from(&[0u8; 32]).is_ok());
        assert!(AsymmetricPublicKey::<V2>::from(&[0u8; 33]).is_err());

        assert!(SymmetricKey::<V2>::from(&[0u8; 31]).is_err());
        assert!(SymmetricKey::<V2>::from(&[0u8; 32]).is_ok());
        assert!(SymmetricKey::<V2>::from(&[0u8; 33]).is_err());

        // Version 4
        assert!(AsymmetricSecretKey::<V4>::from(&[0u8; 31]).is_err());
        assert!(AsymmetricSecretKey::<V4>::from(&[0u8; 32]).is_ok());
        assert!(AsymmetricSecretKey::<V4>::from(&[0u8; 33]).is_err());

        assert!(AsymmetricPublicKey::<V4>::from(&[0u8; 31]).is_err());
        assert!(AsymmetricPublicKey::<V4>::from(&[0u8; 32]).is_ok());
        assert!(AsymmetricPublicKey::<V4>::from(&[0u8; 33]).is_err());

        assert!(SymmetricKey::<V4>::from(&[0u8; 31]).is_err());
        assert!(SymmetricKey::<V4>::from(&[0u8; 32]).is_ok());
        assert!(SymmetricKey::<V4>::from(&[0u8; 33]).is_err());
    }
}
