#![cfg_attr(docsrs, doc(cfg(feature = "paserk")))]

use crate::common::{decode_b64, encode_b64};
use crate::errors::Error;
use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
use crate::version::private::Version;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt::Write;
use core::marker::PhantomData;
use orion::hazardous::hash::blake2::blake2b;
use zeroize::Zeroize;

#[cfg(feature = "v2")]
use crate::version2::V2;

#[cfg(feature = "v3")]
use crate::version3::V3;
#[cfg(feature = "v3")]
use orion::hazardous::hash::sha2::sha384;

#[cfg(feature = "v4")]
use crate::version4::V4;

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

#[cfg(feature = "v2")]
impl FormatAsPaserk for SymmetricKey<V2> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k2.local.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v2")]
impl TryFrom<&str> for SymmetricKey<V2> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k2", "local", V2::LOCAL_KEY)?,
            phantom: PhantomData,
        })
    }
}

#[cfg(feature = "v4")]
impl FormatAsPaserk for SymmetricKey<V4> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k4.local.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v4")]
impl TryFrom<&str> for SymmetricKey<V4> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k4", "local", V4::LOCAL_KEY)?,
            phantom: PhantomData,
        })
    }
}

#[cfg(feature = "v2")]
impl FormatAsPaserk for AsymmetricSecretKey<V2> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k2.secret.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v2")]
impl TryFrom<&str> for AsymmetricSecretKey<V2> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut buf = validate_paserk_string(value, "k2", "secret", V2::SECRET_KEY)?;
        let ret = Self::from(&buf)?;
        buf.iter_mut().zeroize();

        Ok(ret)
    }
}

#[cfg(feature = "v3")]
impl FormatAsPaserk for AsymmetricSecretKey<V3> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k3.secret.")?;
        write.write_str(&encode_b64(&self.bytes).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v3")]
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

#[cfg(feature = "v4")]
impl FormatAsPaserk for AsymmetricSecretKey<V4> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k4.secret.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v4")]
impl TryFrom<&str> for AsymmetricSecretKey<V4> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut buf = validate_paserk_string(value, "k4", "secret", V4::SECRET_KEY)?;
        let ret = Self::from(&buf)?;
        buf.iter_mut().zeroize();

        Ok(ret)
    }
}

#[cfg(feature = "v2")]
impl FormatAsPaserk for AsymmetricPublicKey<V2> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k2.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v2")]
impl TryFrom<&str> for AsymmetricPublicKey<V2> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k2", "public", V2::PUBLIC_KEY)?,
            phantom: PhantomData,
        })
    }
}

#[cfg(feature = "v3")]
impl FormatAsPaserk for AsymmetricPublicKey<V3> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k3.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v3")]
impl TryFrom<&str> for AsymmetricPublicKey<V3> {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: validate_paserk_string(value, "k3", "public", V3::PUBLIC_KEY)?,
            phantom: PhantomData,
        })
    }
}

#[cfg(feature = "v4")]
impl FormatAsPaserk for AsymmetricPublicKey<V4> {
    fn fmt(&self, write: &mut dyn Write) -> core::fmt::Result {
        write.write_str("k4.public.")?;
        write.write_str(&encode_b64(self.as_bytes()).map_err(|_| core::fmt::Error)?)
    }
}

#[cfg(feature = "v4")]
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

#[cfg(feature = "v3")]
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

#[cfg(feature = "v3")]
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

#[cfg(feature = "v2")]
impl From<&SymmetricKey<V2>> for Id {
    fn from(key: &SymmetricKey<V2>) -> Self {
        let header = String::from("k2.lid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

#[cfg(feature = "v4")]
impl From<&SymmetricKey<V4>> for Id {
    fn from(key: &SymmetricKey<V4>) -> Self {
        let header = String::from("k4.lid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

#[cfg(feature = "v2")]
impl From<&AsymmetricSecretKey<V2>> for Id {
    fn from(key: &AsymmetricSecretKey<V2>) -> Self {
        let header = String::from("k2.sid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

#[cfg(feature = "v4")]
impl From<&AsymmetricSecretKey<V4>> for Id {
    fn from(key: &AsymmetricSecretKey<V4>) -> Self {
        let header = String::from("k4.sid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

#[cfg(feature = "v2")]
impl From<&AsymmetricPublicKey<V2>> for Id {
    fn from(key: &AsymmetricPublicKey<V2>) -> Self {
        let header = String::from("k2.pid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(hasher.finalize().unwrap().as_ref()).unwrap();
        debug_assert_eq!(identifier.len(), 44);

        Self { header, identifier }
    }
}

#[cfg(feature = "v4")]
impl From<&AsymmetricPublicKey<V4>> for Id {
    fn from(key: &AsymmetricPublicKey<V4>) -> Self {
        let header = String::from("k4.pid.");
        let mut hasher = blake2b::Blake2b::new(33).unwrap();
        hasher.update(header.as_bytes()).unwrap();

        let mut paserk_string = String::new();
        key.fmt(&mut paserk_string).unwrap();
        hasher.update(paserk_string.as_bytes()).unwrap();
        let identifier = encode_b64(hasher.finalize().unwrap().as_ref()).unwrap();
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

#[cfg(any(feature = "v2", feature = "v3", feature = "v4"))]
impl TryFrom<&str> for Id {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let split = value.split('.').collect::<Vec<&str>>();
        if split.len() != 3 {
            return Err(Error::PaserkParsing);
        }

        let header = match (split[0], split[1]) {
            ("k2", "lid" | "sid" | "pid")
            | ("k3", "sid" | "pid")
            | ("k4", "lid" | "sid" | "pid") => format!("{}.{}.", split[0], split[1]),
            _ => return Err(Error::PaserkParsing),
        };

        let expected_len = match split[0] {
            #[cfg(feature = "v2")]
            "k2" => V2::PASERK_ID,
            #[cfg(feature = "v3")]
            "k3" => V3::PASERK_ID,
            #[cfg(feature = "v4")]
            "k4" => V4::PASERK_ID,
            _ => return Err(Error::PaserkParsing),
        };
        if split[2].len() != expected_len {
            return Err(Error::PaserkParsing);
        }

        Ok(Self {
            header,
            identifier: split[2].to_string(),
        })
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use super::*;

    use ::serde::{Deserialize, Serialize};
    use alloc::string::String;
    use alloc::vec::Vec;
    use hex;
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
        #[serde(rename(deserialize = "expect-fail"))]
        pub(crate) expect_fail: bool,
        pub(crate) key: Option<String>,
        pub(crate) paserk: Option<String>,
        #[serde(rename(deserialize = "public-key"))]
        pub(crate) public_key: Option<String>,
        #[serde(rename(deserialize = "secret-key-seed"))]
        pub(crate) secret_key_seed: Option<String>,
    }

    const TEST_WITH_ALL_ZERO_SEED: [&str; 4] =
        ["k2.secret-1", "k2.sid-1", "k4.secret-1", "k4.sid-1"];

    macro_rules! test_paserk_type {
        ($test_func_name:ident, $key:ident, $version:ident, $path:expr) => {
            #[test]
            pub fn $test_func_name() {
                let file = File::open($path).unwrap();
                let reader = BufReader::new(file);
                let tests: TestFile = serde_json::from_reader(reader).unwrap();

                for test_paserk in tests.tests {
                    if TEST_WITH_ALL_ZERO_SEED.contains(&test_paserk.name.as_str()) {
                        // We require that the public key match the secret seed. Thus,
                        // the first test vectors for PASERK dealing with secret keys
                        // will always fail.
                        continue;
                    }

                    match (test_paserk.expect_fail, test_paserk.paserk, test_paserk.key) {
                        (true, Some(_paserk), Some(_key)) => {
                            unreachable!("This test vectors shouldn't exist")
                        }
                        (true, Some(paserk), None) => {
                            assert!($key::<$version>::try_from(paserk.as_str()).is_err());
                            continue;
                        }
                        (true, None, Some(key)) => {
                            if hex::decode(&key).is_err() {
                                continue; // The case where RSA keys are put in v2
                            }
                            assert!($key::<$version>::from(&hex::decode(&key).unwrap()).is_err());
                            continue;
                        }
                        (false, Some(paserk), Some(key)) => {
                            #[cfg(feature = "serde")]
                            let key_hex = key.clone();
                            let deser = $key::<$version>::try_from(paserk.as_str()).unwrap();
                            let key = $key::<$version>::from(&hex::decode(&key).unwrap()).unwrap();
                            assert_eq!(deser.as_bytes(), key.as_bytes());
                            let mut buf = String::new();
                            key.fmt(&mut buf).unwrap();
                            assert_eq!(paserk, buf);

                            #[cfg(feature = "serde")]
                            {
                                let deser: $key<$version> =
                                    serde_json::from_str(&format!(r#""{paserk}""#)).unwrap();
                                let key = $key::<$version>::from(&hex::decode(&key_hex).unwrap())
                                    .unwrap();
                                assert_eq!(deser.as_bytes(), key.as_bytes());
                                let ser = serde_json::to_string(&key).unwrap();
                                assert_eq!(format!(r#""{paserk}""#), ser);
                            }
                        }
                        _ => unreachable!("This test vectors shouldn't exist"),
                    }
                }
            }
        };
    }

    macro_rules! test_id_type {
        ($test_func_name:ident, $key:ident, $version:ident, $path:expr) => {
            #[test]
            pub fn $test_func_name() {
                let file = File::open($path).unwrap();
                let reader = BufReader::new(file);
                let tests: TestFile = serde_json::from_reader(reader).unwrap();

                for test_paserk in tests.tests {
                    if TEST_WITH_ALL_ZERO_SEED.contains(&test_paserk.name.as_str()) {
                        // We require that the public key match the secret seed. Thus,
                        // the first test vectors for PASERK dealing with secret keys
                        // will always fail.
                        continue;
                    }

                    match (test_paserk.expect_fail, test_paserk.paserk, test_paserk.key) {
                        (true, Some(_paserk), Some(_key)) => {
                            unreachable!("This test vectors shouldn't exist")
                        }
                        (true, Some(_paserk), None) => {
                            unreachable!("This test vectors shouldn't exist")
                        }
                        (true, None, Some(key)) => {
                            if hex::decode(&key).is_err() {
                                continue; // The case where RSA keys are put in v2
                            }
                            assert!($key::<$version>::from(&hex::decode(&key).unwrap()).is_err());
                            continue;
                        }
                        (false, Some(paserk), Some(key)) => {
                            #[cfg(feature = "serde")]
                            let key_hex = key.clone();
                            let key = $key::<$version>::from(&hex::decode(&key).unwrap()).unwrap();

                            let paserk_id = Id::from(&key);
                            let mut buf = String::new();
                            paserk_id.fmt(&mut buf).unwrap();
                            assert_eq!(paserk, buf);

                            #[cfg(feature = "serde")]
                            {
                                let key = $key::<$version>::from(&hex::decode(&key_hex).unwrap())
                                    .unwrap();
                                let paserk_id = Id::from(&key);
                                let mut buf = String::new();
                                paserk_id.fmt(&mut buf).unwrap();

                                let deser: Id =
                                    serde_json::from_str(&format!(r#""{buf}""#)).unwrap();
                                assert_eq!(paserk_id, deser);
                                let ser = serde_json::to_string(&paserk_id).unwrap();
                                assert_eq!(format!(r#""{buf}""#), ser);
                            }
                        }
                        _ => unreachable!("This test vectors shouldn't exist"),
                    }
                }
            }
        };
    }

    #[cfg(test)]
    #[cfg(feature = "v2")]
    mod v2 {
        use super::*;

        test_id_type!(
            test_local_k2_id,
            SymmetricKey,
            V2,
            "./test_vectors/PASERK/k2.lid.json"
        );

        test_id_type!(
            test_secret_k2_id,
            AsymmetricSecretKey,
            V2,
            "./test_vectors/PASERK/k2.sid.json"
        );

        test_id_type!(
            test_public_k2_id,
            AsymmetricPublicKey,
            V2,
            "./test_vectors/PASERK/k2.pid.json"
        );

        test_paserk_type!(
            test_local_k2,
            SymmetricKey,
            V2,
            "./test_vectors/PASERK/k2.local.json"
        );

        test_paserk_type!(
            test_public_k2,
            AsymmetricPublicKey,
            V2,
            "./test_vectors/PASERK/k2.public.json"
        );

        test_paserk_type!(
            test_secret_k2,
            AsymmetricSecretKey,
            V2,
            "./test_vectors/PASERK/k2.secret.json"
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

            assert!(AsymmetricSecretKey::<V2>::try_from("k2.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_ok());
            assert!(AsymmetricSecretKey::<V2>::try_from("k4.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_err());
            assert!(AsymmetricSecretKey::<V2>::try_from("k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_err());
            assert!(AsymmetricSecretKey::<V2>::try_from("k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_err());
        }
    }

    #[cfg(test)]
    #[cfg(feature = "v3")]
    mod v3 {
        use super::*;

        test_id_type!(
            test_secret_k3_id,
            AsymmetricSecretKey,
            V3,
            "./test_vectors/PASERK/k3.sid.json"
        );

        test_id_type!(
            test_public_k3_id,
            AsymmetricPublicKey,
            V3,
            "./test_vectors/PASERK/k3.pid.json"
        );

        test_paserk_type!(
            test_public_k3,
            AsymmetricPublicKey,
            V3,
            "./test_vectors/PASERK/k3.public.json"
        );

        test_paserk_type!(
            test_secret_k3,
            AsymmetricSecretKey,
            V3,
            "./test_vectors/PASERK/k3.secret.json"
        );

        #[test]
        fn test_wrong_version_or_purpose() {
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
        }
    }

    #[cfg(test)]
    #[cfg(feature = "v4")]
    mod v4 {
        use super::*;

        test_id_type!(
            test_local_k4_id,
            SymmetricKey,
            V4,
            "./test_vectors/PASERK/k4.lid.json"
        );

        test_id_type!(
            test_secret_k4_id,
            AsymmetricSecretKey,
            V4,
            "./test_vectors/PASERK/k4.sid.json"
        );

        test_id_type!(
            test_public_k4_id,
            AsymmetricPublicKey,
            V4,
            "./test_vectors/PASERK/k4.pid.json"
        );

        test_paserk_type!(
            test_local_k4,
            SymmetricKey,
            V4,
            "./test_vectors/PASERK/k4.local.json"
        );

        test_paserk_type!(
            test_public_k4,
            AsymmetricPublicKey,
            V4,
            "./test_vectors/PASERK/k4.public.json"
        );

        test_paserk_type!(
            test_secret_k4,
            AsymmetricSecretKey,
            V4,
            "./test_vectors/PASERK/k4.secret.json"
        );

        #[test]
        fn test_wrong_version_or_purpose() {
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

            assert!(AsymmetricSecretKey::<V4>::try_from("k4.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_ok());
            assert!(AsymmetricSecretKey::<V4>::try_from("k2.secret.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_err());
            assert!(AsymmetricSecretKey::<V4>::try_from("k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_err());
            assert!(AsymmetricSecretKey::<V4>::try_from("k2.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8c5WpIyC_5kWKhS8VEYSZ05dYfuTF-ZdQFV4D9vLTcNQ").is_err());
        }
    }

    #[test]
    #[cfg(all(feature = "v4", feature = "v3"))]
    fn test_partial_eq_id() {
        use crate::keys::{AsymmetricKeyPair, Generate};

        let kpv4 = AsymmetricKeyPair::<V4>::generate().unwrap();
        assert_eq!(Id::from(&kpv4.secret), Id::from(&kpv4.secret));
        assert_ne!(Id::from(&kpv4.secret), Id::from(&kpv4.public));
        let kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        assert_ne!(Id::from(&kpv4.secret), Id::from(&kpv3.secret));
    }

    #[test]
    #[cfg(feature = "v4")]
    fn test_validate_paserk_string() {
        assert!(validate_paserk_string("k4.public", "k4", "public", V4::PUBLIC_KEY).is_err());
        assert!(
            validate_paserk_string("k4.public.public.public", "k4", "public", V4::PUBLIC_KEY)
                .is_err()
        );
        let too_long = format!(
            "k4.public.{}",
            encode_b64([0u8; V4::PUBLIC_KEY * 2]).unwrap()
        );
        assert!(validate_paserk_string(&too_long, "k4", "public", V4::PUBLIC_KEY).is_err());
    }
}
