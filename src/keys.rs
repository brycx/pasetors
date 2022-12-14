use crate::errors::Error;
use crate::version::private::Version;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

/// A type `T` that can be generated for a given version `V`.
pub trait Generate<T, V: Version> {
    /// Generate `T`.
    fn generate() -> Result<T, Error>;
}

#[derive(Clone)]
/// A symmetric key used for `.local` tokens, given a version `V`.
pub struct SymmetricKey<V> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) phantom: PhantomData<V>,
}

impl<V: Version> SymmetricKey<V> {
    /// Create a `SymmetricKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Error> {
        V::validate_local_key(bytes)?;

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

impl<V: Version> PartialEq<SymmetricKey<V>> for SymmetricKey<V> {
    fn eq(&self, other: &SymmetricKey<V>) -> bool {
        use subtle::ConstantTimeEq;
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

#[derive(Clone)]
/// An asymmetric secret key used for `.public` tokens, given a version `V`.
///
/// In case of Ed25519, which is used in V2 and V4, this is the seed concatenated with the public key.
pub struct AsymmetricSecretKey<V> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) phantom: PhantomData<V>,
}

impl<V: Version> AsymmetricSecretKey<V> {
    /// Create a `AsymmetricSecretKey` from `bytes`.
    ///
    /// __PANIC__: If the version is V2 or V4, a panic will occur if an all-zero
    /// secret seed is used.
    pub fn from(bytes: &[u8]) -> Result<Self, Error> {
        V::validate_secret_key(bytes)?;

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

impl<V: Version> PartialEq<AsymmetricSecretKey<V>> for AsymmetricSecretKey<V> {
    fn eq(&self, other: &AsymmetricSecretKey<V>) -> bool {
        use subtle::ConstantTimeEq;
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

#[derive(Debug, Clone)]
/// An asymmetric public key used for `.public` tokens, given a version `V`.
pub struct AsymmetricPublicKey<V> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) phantom: PhantomData<V>,
}

impl<V: Version> AsymmetricPublicKey<V> {
    /// Create a `AsymmetricPublicKey` from `bytes`.
    pub fn from(bytes: &[u8]) -> Result<Self, Error> {
        V::validate_public_key(bytes)?;

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

impl<V: Version> PartialEq<AsymmetricPublicKey<V>> for AsymmetricPublicKey<V> {
    fn eq(&self, other: &AsymmetricPublicKey<V>) -> bool {
        use subtle::ConstantTimeEq;
        self.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

#[derive(Debug, Clone)]
/// A keypair of an [`AsymmetricSecretKey`] and its corresponding [`AsymmetricPublicKey`].
pub struct AsymmetricKeyPair<V> {
    /// The [`AsymmetricSecretKey`].
    pub public: AsymmetricPublicKey<V>,
    /// The [`AsymmetricPublicKey`].
    pub secret: AsymmetricSecretKey<V>,
}
