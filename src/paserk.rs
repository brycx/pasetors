#![cfg_attr(docsrs, doc(cfg(feature = "paserk")))]

use crate::common::{decode_b64, encode_b64};
use crate::errors::Error;
use crate::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
use crate::version::private::Version;
use crate::{V2, V3, V4};
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt::Write;
use core::marker::PhantomData;
use orion::hazardous::hash::blake2::blake2b;
use orion::hazardous::hash::sha2::sha384;
use zeroize::Zeroize;

/// Validate an input string to check if it is a well-formatted PASERK.
///
/// Return the base64-encoded part of the serialized string.
fn validate_paserk_string(
    input: &str,
    version_id: &str,
    type_id: &str,
    expected_len: usize,
) -> Result<Vec<u8>, Error> {
    let split = input.split('.').collect::<Vec<&str>>();
    if split.len() != 3 {
        return Err(Error::PaserkParsing);
    }

    if split[0] == version_id && split[1] == type_id {
        let ret = decode_b64(split[2])?;
        if ret.len() != expected_len {
            return Err(Error::PaserkParsing);
        }

        Ok(ret)
    } else {
        Err(Error::PaserkParsing)
    }
}

/// A trait for serializing a type as PASERK.
pub trait FormatAsPaserk {
    /// Format a key as PASERK.
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result;
}

impl FormatAsPaserk for SymmetricKey<V2> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k2.local.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<&str> for SymmetricKey<V2> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k2", "local", V2::LOCAL_KEY)?,
            phantom: PhantomData,
        })
    }
}

impl FormatAsPaserk for SymmetricKey<V4> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k4.local.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<&str> for SymmetricKey<V4> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k4", "local", V4::LOCAL_KEY)?,
            phantom: PhantomData,
        })
    }
}

impl FormatAsPaserk for AsymmetricKeyPair<V2> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k2.secret.")?;

        // See spec: "Here, Ed25519 secret key means the clamped 32-byte seed followed by the
        // 32-byte public key, as used in the NaCl and libsodium APIs, rather than just the
        // clamped 32-byte seed."
        let mut buf = [0u8; V2::SECRET_KEY + V2::PUBLIC_KEY];
        buf[..V2::SECRET_KEY].copy_from_slice(self.secret.as_bytes());
        buf[V2::SECRET_KEY..].copy_from_slice(self.public.as_bytes());
        write.write_str(&encode_b64(buf).map_err(|_| core::fmt::Error)?)?;
        buf.iter_mut().zeroize();

        Ok(())
    }
}

impl TryFrom<&str> for AsymmetricKeyPair<V2> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut buf =
            validate_paserk_string(value, "k2", "secret", V2::SECRET_KEY + V2::PUBLIC_KEY)?;
        let ret = Self {
            secret: AsymmetricSecretKey::from(&buf[..V2::SECRET_KEY])?,
            public: AsymmetricPublicKey::from(&buf[V2::SECRET_KEY..])?,
        };
        buf.iter_mut().zeroize();

        Ok(ret)
    }
}

impl FormatAsPaserk for AsymmetricSecretKey<V3> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k3.secret.")?;
        write.write_str(&encode_b64(&self.bytes).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<&str> for AsymmetricSecretKey<V3> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let buf = validate_paserk_string(value, "k3", "secret", V3::SECRET_KEY)?;
        let ret = Self {
            bytes: buf,
            phantom: PhantomData,
        };

        Ok(ret)
    }
}

impl FormatAsPaserk for AsymmetricKeyPair<V4> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k4.secret.")?;

        let mut buf = [0u8; V4::SECRET_KEY + V4::PUBLIC_KEY];
        buf[..V4::SECRET_KEY].copy_from_slice(self.secret.as_bytes());
        buf[V4::SECRET_KEY..].copy_from_slice(self.public.as_bytes());
        write.write_str(&encode_b64(buf).map_err(|_| core::fmt::Error)?)?;
        buf.iter_mut().zeroize();

        Ok(())
    }
}

impl TryFrom<&str> for AsymmetricKeyPair<V4> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut buf =
            validate_paserk_string(value, "k4", "secret", V4::SECRET_KEY + V4::PUBLIC_KEY)?;
        let ret = Self {
            secret: AsymmetricSecretKey::from(&buf[..V4::SECRET_KEY])?,
            public: AsymmetricPublicKey::from(&buf[V4::SECRET_KEY..])?,
        };
        buf.iter_mut().zeroize();

        Ok(ret)
    }
}

impl FormatAsPaserk for AsymmetricPublicKey<V2> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k2.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<&str> for AsymmetricPublicKey<V2> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k2", "public", V2::PUBLIC_KEY)?,
            phantom: PhantomData,
        })
    }
}

impl FormatAsPaserk for AsymmetricPublicKey<V3> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k3.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<&str> for AsymmetricPublicKey<V3> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k3", "public", V3::PUBLIC_KEY)?,
            phantom: PhantomData,
        })
    }
}

impl FormatAsPaserk for AsymmetricPublicKey<V4> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k4.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<&str> for AsymmetricPublicKey<V4> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k4", "public", V4::PUBLIC_KEY)?,
            phantom: PhantomData,
        })
    }
}

#[derive(Debug, Clone)]
/// PASERK IDs.
///
/// This operation calculates the unique ID for a given PASERK.
///
/// See: <https://github.com/paseto-standard/paserk/blob/master/operations/ID.md>
pub struct Id {
    header: String,
    identifier: String,
}

impl PartialEq<Id> for Id {
    fn eq(&self, other: &Id) -> bool {
        use subtle::ConstantTimeEq;
        (self.header.as_bytes().ct_eq(other.header.as_bytes())
            & self
                .identifier
                .as_bytes()
                .ct_eq(other.identifier.as_bytes()))
        .into()
    }
}

impl From<&AsymmetricSecretKey<V3>> for Id {
    fn from(key: &AsymmetricSecretKey<V3>) -> Self {
        let header = String::from("k3.sid.");
        let mut hasher = sha384::Sha384::new();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()[..33]).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl From<&AsymmetricPublicKey<V3>> for Id {
    fn from(key: &AsymmetricPublicKey<V3>) -> Self {
        let header = String::from("k3.pid.");
        let mut hasher = sha384::Sha384::new();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()[..33]).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl From<&SymmetricKey<V2>> for Id {
    fn from(key: &SymmetricKey<V2>) -> Self {
        let header = String::from("k2.lid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl From<&SymmetricKey<V4>> for Id {
    fn from(key: &SymmetricKey<V4>) -> Self {
        let header = String::from("k4.lid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl From<&AsymmetricKeyPair<V2>> for Id {
    fn from(key: &AsymmetricKeyPair<V2>) -> Self {
        let header = String::from("k2.sid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl From<&AsymmetricKeyPair<V4>> for Id {
    fn from(key: &AsymmetricKeyPair<V4>) -> Self {
        let header = String::from("k4.sid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl From<&AsymmetricPublicKey<V2>> for Id {
    fn from(key: &AsymmetricPublicKey<V2>) -> Self {
        let header = String::from("k2.pid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl From<&AsymmetricPublicKey<V4>> for Id {
    fn from(key: &AsymmetricPublicKey<V4>) -> Self {
        let header = String::from("k4.pid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(&hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

impl FormatAsPaserk for Id {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str(&self.header)?;
        write.write_str(&self.identifier)
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    use alloc::string::String;
    use alloc::vec::Vec;
    use hex;
    use serde::{Deserialize, Serialize};
    use std::fs::File;
    use std::io::BufReader;

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct TestFile {
        pub(crate) name: String,
        pub(crate) tests: Vec<PaserkTest>,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct PaserkTest {
        pub(crate) name: String,
        pub(crate) key: String,
        pub(crate) paserk: String,
        #[serde(rename(deserialize = "public-key"))]
        pub(crate) public_key: Option<String>,
        #[serde(rename(deserialize = "secret-key-seed"))]
        pub(crate) secret_key_seed: Option<String>,
    }

    macro_rules! test_id_type {
        ($test_func_name:ident, $key:ident, $version:ident, $path:expr) => {
            #[test]
            pub fn $test_func_name() {
                let file = File::open($path).unwrap();
                let reader = BufReader::new(file);
                let tests: TestFile = serde_json::from_reader(reader).unwrap();

                for test_paserk in tests.tests {
                    let key =
                        $key::<$version>::from(&hex::decode(&test_paserk.key).unwrap()).unwrap();

                    let paserk_id = Id::from(&key);
                    let mut buf = String::new();
                    paserk_id.fmt(&mut buf).unwrap();
                    assert_eq!(test_paserk.paserk, buf);
                }
            }
        };
    }

    test_id_type!(
        test_local_k2_id,
        SymmetricKey,
        V2,
        "./test_vectors/PASERK/k2.lid.json"
    );
    test_id_type!(
        test_local_k4_id,
        SymmetricKey,
        V4,
        "./test_vectors/PASERK/k4.lid.json"
    );
    test_id_type!(
        test_secret_k2_id,
        AsymmetricKeyPair,
        V2,
        "./test_vectors/PASERK/k2.sid.json"
    );
    test_id_type!(
        test_secret_k3_id,
        AsymmetricSecretKey,
        V3,
        "./test_vectors/PASERK/k3.sid.json"
    );
    test_id_type!(
        test_secret_k4_id,
        AsymmetricKeyPair,
        V4,
        "./test_vectors/PASERK/k4.sid.json"
    );
    test_id_type!(
        test_public_k2_id,
        AsymmetricPublicKey,
        V2,
        "./test_vectors/PASERK/k2.pid.json"
    );
    test_id_type!(
        test_public_k3_id,
        AsymmetricPublicKey,
        V3,
        "./test_vectors/PASERK/k3.pid.json"
    );
    test_id_type!(
        test_public_k4_id,
        AsymmetricPublicKey,
        V4,
        "./test_vectors/PASERK/k4.pid.json"
    );

    macro_rules! test_paserk_type {
        ($test_func_name:ident, $key:ident, $version:ident, $path:expr) => {
            #[test]
            pub fn $test_func_name() {
                let file = File::open($path).unwrap();
                let reader = BufReader::new(file);
                let tests: TestFile = serde_json::from_reader(reader).unwrap();

                for test_paserk in tests.tests {
                    let deser = $key::<$version>::try_from(test_paserk.paserk.as_str()).unwrap();
                    let key =
                        $key::<$version>::from(&hex::decode(&test_paserk.key).unwrap()).unwrap();
                    assert_eq!(deser.as_bytes(), key.as_bytes());
                    let mut buf = String::new();
                    key.fmt(&mut buf).unwrap();
                    assert_eq!(test_paserk.paserk, buf);
                }
            }
        };
    }

    test_paserk_type!(
        test_local_k2,
        SymmetricKey,
        V2,
        "./test_vectors/PASERK/k2.local.json"
    );
    test_paserk_type!(
        test_local_k4,
        SymmetricKey,
        V4,
        "./test_vectors/PASERK/k4.local.json"
    );
    test_paserk_type!(
        test_public_k2,
        AsymmetricPublicKey,
        V2,
        "./test_vectors/PASERK/k2.public.json"
    );
    test_paserk_type!(
        test_public_k3,
        AsymmetricPublicKey,
        V3,
        "./test_vectors/PASERK/k3.public.json"
    );
    test_paserk_type!(
        test_public_k4,
        AsymmetricPublicKey,
        V4,
        "./test_vectors/PASERK/k4.public.json"
    );
    test_paserk_type!(
        test_secret_k2,
        AsymmetricKeyPair,
        V2,
        "./test_vectors/PASERK/k2.secret.json"
    );
    test_paserk_type!(
        test_secret_k3,
        AsymmetricSecretKey,
        V3,
        "./test_vectors/PASERK/k3.secret.json"
    );
    test_paserk_type!(
        test_secret_k4,
        AsymmetricKeyPair,
        V4,
        "./test_vectors/PASERK/k4.secret.json"
    );

    #[test]
    fn test_wrong_version_or_purpose() {
        assert!(SymmetricKey::<V2>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_ok());
        assert!(SymmetricKey::<V2>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(SymmetricKey::<V2>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(SymmetricKey::<V2>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());

        assert!(SymmetricKey::<V4>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_ok());
        assert!(SymmetricKey::<V4>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(SymmetricKey::<V4>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(SymmetricKey::<V4>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());

        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_ok());
        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V3>::try_from(
            "k3.public.AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_ok());
        assert!(AsymmetricPublicKey::<V3>::try_from(
            "k4.public.AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V3>::try_from(
            "k3.local.AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V3>::try_from(
            "k4.local.AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_ok());
        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());

        assert!(AsymmetricKeyPair::<V2>::try_from("k2.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_ok());
        assert!(AsymmetricKeyPair::<V2>::try_from("k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_err());
        assert!(AsymmetricKeyPair::<V2>::try_from("k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_err());
        assert!(AsymmetricKeyPair::<V2>::try_from("k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_err());

        assert!(AsymmetricSecretKey::<V3>::try_from(
            "k3.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
        )
        .is_ok());
        assert!(AsymmetricSecretKey::<V3>::try_from(
            "k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
        )
        .is_err());
        assert!(AsymmetricSecretKey::<V3>::try_from(
            "k3.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
        )
        .is_err());
        assert!(AsymmetricSecretKey::<V3>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
        )
        .is_err());

        assert!(AsymmetricKeyPair::<V4>::try_from("k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_ok());
        assert!(AsymmetricKeyPair::<V4>::try_from("k2.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_err());
        assert!(AsymmetricKeyPair::<V4>::try_from("k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_err());
        assert!(AsymmetricKeyPair::<V4>::try_from("k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ").is_err());
    }
}
