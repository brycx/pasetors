use crate::common::{decode_b64, encode_b64};
use crate::errors::Error;
use crate::keys::private::Version;
use crate::keys::{
    AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey, V2, V4,
};
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
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
    fn fmt(&self, write: &mut dyn core::fmt::Write) -> core::fmt::Result;
}

impl FormatAsPaserk for SymmetricKey<V2> {
    fn fmt(&self, write: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write.write_str("k2.local.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<String> for SymmetricKey<V2> {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value.as_str(), "k2", "local", V2::LOCAL)?,
            phantom: core::marker::PhantomData,
        })
    }
}

impl FormatAsPaserk for SymmetricKey<V4> {
    fn fmt(&self, write: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write.write_str("k4.local.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<String> for SymmetricKey<V4> {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value.as_str(), "k4", "local", V4::LOCAL)?,
            phantom: core::marker::PhantomData,
        })
    }
}

impl FormatAsPaserk for AsymmetricKeyPair<V2> {
    fn fmt(&self, write: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write.write_str("k2.secret.")?;

        // See spec: "Here, Ed25519 secret key means the clamped 32-byte seed followed by the
        // 32-byte public key, as used in the NaCl and libsodium APIs, rather than just the
        // clamped 32-byte seed."
        let mut buf = [0u8; V2::SECRET + V2::PUBLIC];
        buf[..V2::SECRET].copy_from_slice(self.secret.as_bytes());
        buf[V2::SECRET..].copy_from_slice(self.public.as_bytes());
        write.write_str(&encode_b64(buf).map_err(|_| core::fmt::Error)?)?;
        buf.iter_mut().zeroize();

        Ok(())
    }
}

impl TryFrom<String> for AsymmetricKeyPair<V2> {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut buf =
            validate_paserk_string(value.as_str(), "k2", "secret", V2::SECRET + V2::PUBLIC)?;
        let ret = Self {
            secret: AsymmetricSecretKey::from(&buf[..V2::SECRET])?,
            public: AsymmetricPublicKey::from(&buf[V2::SECRET..])?,
        };
        buf.iter_mut().zeroize();

        Ok(ret)
    }
}

impl FormatAsPaserk for AsymmetricKeyPair<V4> {
    fn fmt(&self, write: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write.write_str("k4.secret.")?;

        let mut buf = [0u8; V4::SECRET + V4::LOCAL];
        buf[..V4::SECRET].copy_from_slice(self.secret.as_bytes());
        buf[V4::SECRET..].copy_from_slice(self.public.as_bytes());
        write.write_str(&encode_b64(buf).map_err(|_| core::fmt::Error)?)?;
        buf.iter_mut().zeroize();

        Ok(())
    }
}

impl TryFrom<String> for AsymmetricKeyPair<V4> {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut buf =
            validate_paserk_string(value.as_str(), "k4", "secret", V4::SECRET + V4::PUBLIC)?;
        let ret = Self {
            secret: AsymmetricSecretKey::from(&buf[..V4::SECRET])?,
            public: AsymmetricPublicKey::from(&buf[V4::SECRET..])?,
        };
        buf.iter_mut().zeroize();

        Ok(ret)
    }
}

impl FormatAsPaserk for AsymmetricPublicKey<V2> {
    fn fmt(&self, write: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write.write_str("k2.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<String> for AsymmetricPublicKey<V2> {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value.as_str(), "k2", "public", V2::PUBLIC)?,
            phantom: core::marker::PhantomData,
        })
    }
}

impl FormatAsPaserk for AsymmetricPublicKey<V4> {
    fn fmt(&self, write: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write.write_str("k4.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

impl TryFrom<String> for AsymmetricPublicKey<V4> {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value.as_str(), "k4", "public", V4::PUBLIC)?,
            phantom: core::marker::PhantomData,
        })
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

    macro_rules! test_paserk_type {
        ($test_func_name:ident, $key:ident, $version:ident, $path:expr) => {
            #[test]
            pub fn $test_func_name() {
                let file = File::open($path).unwrap();
                let reader = BufReader::new(file);
                let tests: TestFile = serde_json::from_reader(reader).unwrap();

                for test_paserk in tests.tests {
                    let deser = $key::<$version>::try_from(test_paserk.paserk.clone()).unwrap();
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
        test_secret_k4,
        AsymmetricKeyPair,
        V4,
        "./test_vectors/PASERK/k4.secret.json"
    );

    #[test]
    fn test_wrong_version_or_purpose() {
        assert!(SymmetricKey::<V2>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_ok());
        assert!(SymmetricKey::<V2>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(SymmetricKey::<V2>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(SymmetricKey::<V2>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());

        assert!(SymmetricKey::<V4>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_ok());
        assert!(SymmetricKey::<V4>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(SymmetricKey::<V4>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(SymmetricKey::<V4>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());

        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_ok());
        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V2>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());

        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k4.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_ok());
        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k2.public.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());
        assert!(AsymmetricPublicKey::<V4>::try_from(
            "k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
        )
        .is_err());

        assert!(AsymmetricKeyPair::<V2>::try_from("k2.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_ok());
        assert!(AsymmetricKeyPair::<V2>::try_from("k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_err());
        assert!(AsymmetricKeyPair::<V2>::try_from("k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_err());
        assert!(AsymmetricKeyPair::<V2>::try_from("k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_err());

        assert!(AsymmetricKeyPair::<V4>::try_from("k4.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_ok());
        assert!(AsymmetricKeyPair::<V4>::try_from("k2.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_err());
        assert!(AsymmetricKeyPair::<V4>::try_from("k4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_err());
        assert!(AsymmetricKeyPair::<V4>::try_from("k2.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ".to_string()).is_err());
    }
}
