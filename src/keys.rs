use crate::errors::Error;
use crate::version::private::Version;
use crate::V4;
use alloc::vec::Vec;
#[cfg(feature = "v3")]
use core::convert::TryFrom;
use core::fmt::Debug;
use core::marker::PhantomData;

#[cfg(feature = "v2")]
use crate::V2;

#[cfg(feature = "v3")]
use crate::V3;

/// A type `T` that can be generated for a given version `V`.
pub trait Generate<T, V: Version> {
    /// Generate `T`.
    fn generate() -> Result<T, Error>;
}

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

/// An asymmetric secret key used for `.public` tokens, given a version `V`.
pub struct AsymmetricSecretKey<V> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) phantom: PhantomData<V>,
}

impl<V: Version> AsymmetricSecretKey<V> {
    /// Create a `AsymmetricSecretKey` from `bytes`.
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

#[derive(Debug)]
/// A keypair of an [`AsymmetricSecretKey`] and its corresponding [`AsymmetricPublicKey`].
pub struct AsymmetricKeyPair<V> {
    /// The [`AsymmetricSecretKey`].
    pub public: AsymmetricPublicKey<V>,
    /// The [`AsymmetricPublicKey`].
    pub secret: AsymmetricSecretKey<V>,
}

#[cfg_attr(docsrs, doc(cfg(feature = "v3")))]
#[cfg(feature = "v3")]
impl TryFrom<&AsymmetricSecretKey<V3>> for AsymmetricPublicKey<V3> {
    type Error = Error;

    fn try_from(value: &AsymmetricSecretKey<V3>) -> Result<Self, Self::Error> {
        use p384_rs::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes(value.as_bytes()).map_err(|_| Error::Key)?;
        AsymmetricPublicKey::<V3>::from(sk.verifying_key().to_encoded_point(true).as_bytes())
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
#[cfg(feature = "v2")]
impl Generate<AsymmetricKeyPair<V2>, V2> for AsymmetricKeyPair<V2> {
    fn generate() -> Result<AsymmetricKeyPair<V2>, Error> {
        use ed25519_compact::KeyPair;
        // TODO: This panics. catch_unwind and propagate
        let key_pair = KeyPair::generate();

        let secret = AsymmetricSecretKey::<V2>::from(&key_pair.sk[..32])
            .map_err(|_| Error::KeyGeneration)?;
        let public = AsymmetricPublicKey::<V2>::from(key_pair.pk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;

        Ok(Self { public, secret })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
#[cfg(feature = "v2")]
impl Generate<SymmetricKey<V2>, V2> for SymmetricKey<V2> {
    fn generate() -> Result<SymmetricKey<V2>, Error> {
        let mut rng_bytes = vec![0u8; V2::LOCAL_KEY];
        V2::validate_local_key(&rng_bytes)?;
        getrandom::getrandom(&mut rng_bytes)?;

        Ok(Self {
            bytes: rng_bytes,
            phantom: PhantomData,
        })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "v3")))]
#[cfg(feature = "v3")]
impl Generate<AsymmetricKeyPair<V3>, V3> for AsymmetricKeyPair<V3> {
    fn generate() -> Result<AsymmetricKeyPair<V3>, Error> {
        use p384_rs::ecdsa::{SigningKey, VerifyingKey};
        use rand_core::OsRng;

        let key = SigningKey::random(&mut OsRng);

        let public = AsymmetricPublicKey::<V3>::from(
            VerifyingKey::from(&key).to_encoded_point(true).as_ref(),
        )?;
        let secret = AsymmetricSecretKey::<V3>::from(key.to_bytes().as_slice())?;

        Ok(Self { public, secret })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "v4")))]
#[cfg(feature = "v4")]
impl Generate<SymmetricKey<V4>, V4> for SymmetricKey<V4> {
    fn generate() -> Result<SymmetricKey<V4>, Error> {
        let mut rng_bytes = vec![0u8; V4::LOCAL_KEY];
        V4::validate_local_key(&rng_bytes)?;
        getrandom::getrandom(&mut rng_bytes)?;

        Ok(Self {
            bytes: rng_bytes,
            phantom: PhantomData,
        })
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "v4")))]
#[cfg(feature = "v4")]
impl Generate<AsymmetricKeyPair<V4>, V4> for AsymmetricKeyPair<V4> {
    fn generate() -> Result<AsymmetricKeyPair<V4>, Error> {
        use ed25519_compact::KeyPair;
        // TODO: This panics. catch_unwind and propagate
        let key_pair = KeyPair::generate();

        let secret = AsymmetricSecretKey::<V4>::from(&key_pair.sk[..32])
            .map_err(|_| Error::KeyGeneration)?;
        let public = AsymmetricPublicKey::<V4>::from(key_pair.pk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;

        Ok(Self { public, secret })
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
// NOTE: Only intended for V2/V4 testing purposes.
impl<V: Version> AsymmetricKeyPair<V> {
    pub(crate) fn from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != V2::SECRET_KEY + V2::PUBLIC_KEY {
            return Err(Error::PaserkParsing);
        }

        Ok(Self {
            secret: AsymmetricSecretKey::from(&bytes[..V2::SECRET_KEY])?,
            public: AsymmetricPublicKey::from(&bytes[V2::SECRET_KEY..])?,
        })
    }

    pub(crate) fn as_bytes<'a>(&self) -> [u8; 64] {
        let mut buf = [0u8; V2::SECRET_KEY + V2::PUBLIC_KEY];
        buf[..V2::SECRET_KEY].copy_from_slice(self.secret.as_bytes());
        buf[V2::SECRET_KEY..].copy_from_slice(self.public.as_bytes());

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_gen() {
        let randomv2 = SymmetricKey::<V2>::generate().unwrap();
        let randomv4 = SymmetricKey::<V4>::generate().unwrap();

        assert_ne!(randomv2.as_bytes(), &[0u8; 32]);
        assert_ne!(randomv4.as_bytes(), &[0u8; 32]);
    }

    #[test]
    #[should_panic]
    fn test_v3_local_not_implemented() {
        assert!(SymmetricKey::<V3>::from(&[0u8; 32]).is_ok());
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

        // Version 3
        assert!(AsymmetricSecretKey::<V3>::from(&[0u8; 47]).is_err());
        assert!(AsymmetricSecretKey::<V3>::from(&[0u8; 48]).is_ok());
        assert!(AsymmetricSecretKey::<V3>::from(&[0u8; 49]).is_err());

        let mut pk2 = [0u8; 49];
        pk2[0] = 0x02;
        let mut pk3 = [0u8; 49];
        pk3[0] = 0x03;
        assert!(AsymmetricPublicKey::<V3>::from(&[0u8; 48]).is_err());
        assert!(AsymmetricPublicKey::<V3>::from(&[0u8; 49]).is_err());
        assert!(AsymmetricPublicKey::<V3>::from(&pk2).is_ok());
        assert!(AsymmetricPublicKey::<V3>::from(&pk3).is_ok());
        assert!(AsymmetricPublicKey::<V3>::from(&[0u8; 50]).is_err());

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

    #[cfg(feature = "v3")]
    #[test]
    fn try_from_secret_to_public_v3() {
        let kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        let pubv3 = AsymmetricPublicKey::<V3>::try_from(&kpv3.secret).unwrap();
        assert_eq!(pubv3.as_bytes(), kpv3.public.as_bytes());
    }
}
