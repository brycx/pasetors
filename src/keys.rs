use crate::errors::Errors;
use alloc::vec::Vec;
use core::fmt::Debug;
use std::marker::PhantomData;

/// Version 2 of the PASETO spec.
pub struct V2;
/// Version 4 of the PASETO spec.
pub struct V4;

mod private {
    // Since this trait is in a private module it
    // cannot be implemented from other crates.
    // This prevents users from implementing this trait themselves,
    // possibly defining wrong keys.
    pub trait PrivateTrait {}
}

/// A marker-trait for a key that is either [`V2`] or [`V4`].
pub trait V2orV4: private::PrivateTrait {}
impl V2orV4 for V2 {}
impl V2orV4 for V4 {}
impl private::PrivateTrait for V2 {}
impl private::PrivateTrait for V4 {}

const V2_KEYSIZE: usize = 32;
const V4_KEYSIZE: usize = V2_KEYSIZE;

/// A symmetric key used for `.local` tokens, given a version `V`.
pub struct SymmetricKey<V> {
    bytes: Vec<u8>,
    phantom: PhantomData<V>,
}

impl<V> Debug for SymmetricKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SymmetricKey {{***OMITTED***}}")
    }
}

impl<V> Drop for SymmetricKey<V> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.iter_mut().zeroize();
    }
}

impl<V: V2orV4> SymmetricKey<V> {
    /// Randomly generate a `SymmetricKey`.
    pub fn gen() -> Result<Self, Errors> {
        let mut rng_bytes = vec![0u8; V4_KEYSIZE];
        getrandom::getrandom(&mut rng_bytes)?;

        Ok(Self {
            bytes: rng_bytes,
            phantom: PhantomData,
        })
    }

    /// Create a `SymmetricKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Errors> {
        if bytes.len() != V4_KEYSIZE {
            return Err(Errors::KeyError);
        }

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

/// An asymmetric secret key used for `.public` tokens, given a version `V`.
pub struct AsymmetricSecretKey<V> {
    bytes: Vec<u8>,
    phantom: PhantomData<V>,
}

impl<V> Debug for AsymmetricSecretKey<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AsymmetricSecretKey {{***OMITTED***}}")
    }
}

impl<V> Drop for AsymmetricSecretKey<V> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.iter_mut().zeroize();
    }
}

impl<V: V2orV4> AsymmetricSecretKey<V> {
    /// Create an `AsymmetricSecretKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Errors> {
        if bytes.len() != ed25519_dalek::SECRET_KEY_LENGTH {
            return Err(Errors::KeyError);
        }

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
/// An asymmetric public key used for `.public` tokens, given a version `V`.
pub struct AsymmetricPublicKey<V> {
    bytes: Vec<u8>,
    phantom: PhantomData<V>,
}

impl<V: V2orV4> AsymmetricPublicKey<V> {
    /// Create an `AsymmetricPublicKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Errors> {
        if bytes.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
            return Err(Errors::KeyError);
        }

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
