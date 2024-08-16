#![cfg_attr(docsrs, doc(cfg(feature = "v3")))]

//!
//! This is an implementation of the [version 3 specification of PASETO](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign).
//!
//! The following points apply to this implementation, in regards to the specification:
//! - PASETO requires the use of compressed public keys. If these are not readily supported in a given
//! setting, [UncompressedPublicKey] and [AsymmetricPublicKey<V3>] conversions can be used to obtain
//! the compressed form.
//! - PASETO recommends use of deterministic nonces ([RFC 6979]) which this library also uses.
//! - Hedged signatures, according to the PASETO spec, are not used.
//!
//! [AsymmetricPublicKey<V3>]: crate::keys::AsymmetricPublicKey
//! [UncompressedPublicKey]: crate::version3::UncompressedPublicKey
//! [RFC 6979]: https://tools.ietf.org/html/rfc6979

use core::marker::PhantomData;

use crate::common::{encode_b64, validate_footer_untrusted_token};
use crate::errors::Error;
use crate::keys::{AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate};
use crate::pae;
use crate::token::{Public, TrustedToken, UntrustedToken};
use crate::version::private::Version;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use p384::ecdsa::{
    signature::DigestSigner, signature::DigestVerifier, Signature, SigningKey, VerifyingKey,
};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::PublicKey;
use rand_core::OsRng;
use sha2::Digest;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Version 3 of the PASETO spec.
pub struct V3;

impl Version for V3 {
    const LOCAL_KEY: usize = 32;
    const SECRET_KEY: usize = 48;
    const PUBLIC_KEY: usize = 49;
    const PUBLIC_SIG: usize = 96;
    const LOCAL_NONCE: usize = 32;
    const LOCAL_TAG: usize = 48;
    const PUBLIC_HEADER: &'static str = "v3.public.";
    const LOCAL_HEADER: &'static str = "v3.local.";
    #[cfg(feature = "paserk")]
    const PASERK_ID: usize = 44;

    fn validate_local_key(_key_bytes: &[u8]) -> Result<(), Error> {
        unimplemented!();
    }

    fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::SECRET_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::PUBLIC_KEY {
            return Err(Error::Key);
        }
        if key_bytes[0] != 0x02 && key_bytes[0] != 0x03 {
            return Err(Error::Key);
        }

        Ok(())
    }
}

impl TryFrom<&AsymmetricSecretKey<V3>> for AsymmetricPublicKey<V3> {
    type Error = Error;

    fn try_from(value: &AsymmetricSecretKey<V3>) -> Result<Self, Self::Error> {
        let sk = SigningKey::from_bytes(value.as_bytes().into()).map_err(|_| Error::Key)?;
        AsymmetricPublicKey::<V3>::from(sk.verifying_key().to_encoded_point(true).as_bytes())
    }
}

impl Generate<AsymmetricKeyPair<V3>, V3> for AsymmetricKeyPair<V3> {
    fn generate() -> Result<AsymmetricKeyPair<V3>, Error> {
        let key = SigningKey::random(&mut OsRng);

        let public = AsymmetricPublicKey::<V3>::from(
            VerifyingKey::from(&key).to_encoded_point(true).as_ref(),
        )?;
        let secret = AsymmetricSecretKey::<V3>::from(key.to_bytes().as_slice())?;

        Ok(Self { public, secret })
    }
}

/// This struct represents a uncompressed public key for P384, encoded in big-endian using:
/// Octet-String-to-Elliptic-Curve-Point algorithm in SEC 1: Elliptic Curve Cryptography, Version 2.0.
///
/// Format: `[0x04 || x || y]`
///
/// This is provided to be able to convert uncompressed keys to compressed ones, as compressed is
/// required by PASETO and what an [`AsymmetricPublicKey<V3>`] represents.
pub struct UncompressedPublicKey(PublicKey);

impl TryFrom<&[u8]> for UncompressedPublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // PublicKey::from_sec1_bytes accepts both uncompressed and compressed points
        // but we need to make the distiction here.
        if value.len() != 97 && value[0] != 4 {
            return Err(Error::Key);
        }

        let pk = PublicKey::from_sec1_bytes(value).map_err(|_| Error::Key)?;

        Ok(Self(pk))
    }
}

impl TryFrom<&AsymmetricPublicKey<V3>> for UncompressedPublicKey {
    type Error = Error;

    fn try_from(value: &AsymmetricPublicKey<V3>) -> Result<Self, Self::Error> {
        // PublicKey::from_sec1_bytes accepts both uncompressed and compressed points
        // but we need to make the distiction here.
        if value.as_bytes()[0] != 2 && value.as_bytes()[0] != 3 {
            return Err(Error::Key);
        }

        let pk = PublicKey::from_sec1_bytes(value.as_bytes()).map_err(|_| Error::Key)?;

        Ok(UncompressedPublicKey(pk))
    }
}

impl TryFrom<&UncompressedPublicKey> for AsymmetricPublicKey<V3> {
    type Error = Error;

    fn try_from(value: &UncompressedPublicKey) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: value.0.to_encoded_point(true).as_ref().to_vec(),
            phantom: PhantomData,
        })
    }
}

/// PASETO v3 public tokens.
pub struct PublicToken;

impl PublicToken {
    /// The header and purpose for the public token: `v3.public.`.
    pub const HEADER: &'static str = "v3.public.";

    /// Create a public token.
    ///
    /// The `secret_key` **must** be in big-endian.
    pub fn sign(
        secret_key: &AsymmetricSecretKey<V3>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let signing_key =
            SigningKey::from_bytes(secret_key.as_bytes().into()).map_err(|_| Error::Key)?;
        let public_key = VerifyingKey::from(&signing_key).to_encoded_point(true);

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);
        let m2 = pae::pae(&[public_key.as_ref(), Self::HEADER.as_bytes(), message, f, i])?;

        let mut msg_digest = sha2::Sha384::new();
        msg_digest.update(m2);

        let sig: Signature = signing_key
            .try_sign_digest(msg_digest)
            .map_err(|_| Error::Signing)?;
        debug_assert_eq!(sig.to_bytes().len(), V3::PUBLIC_SIG);

        let mut m_sig: Vec<u8> = Vec::from(message);
        m_sig.extend_from_slice(&sig.to_bytes());

        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(m_sig)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Verify a public token.
    ///
    /// The `public_key` **must** be in big-endian.
    ///
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn verify(
        public_key: &AsymmetricPublicKey<V3>,
        token: &UntrustedToken<Public, V3>,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let i = implicit_assert.unwrap_or(&[]);
        let sm = token.untrusted_message();
        let m = token.untrusted_payload();
        let s = Signature::try_from(sm[m.len()..m.len() + V3::PUBLIC_SIG].as_ref())
            .map_err(|_| Error::TokenValidation)?;

        let m2 = pae::pae(&[public_key.as_bytes(), Self::HEADER.as_bytes(), m, f, i])?;

        let verifying_key =
            VerifyingKey::from_sec1_bytes(public_key.as_bytes()).map_err(|_| Error::Key)?;

        let mut msg_digest = sha2::Sha384::new();
        msg_digest.update(m2);
        verifying_key
            .verify_digest(msg_digest, &s)
            .map_err(|_| Error::TokenValidation)?;

        TrustedToken::_new(Self::HEADER, m, f, i)
    }
}

#[cfg(test)]
mod test_regression {
    use super::*;
    use crate::keys::AsymmetricPublicKey;
    use core::convert::TryFrom;
    use p384::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn fuzzer_regression_1() {
        let pk_bytes: [u8; 97] = [
            4, 0, 205, 193, 144, 253, 175, 61, 67, 178, 31, 65, 80, 197, 219, 197, 12, 136, 239,
            15, 12, 155, 112, 129, 17, 35, 64, 33, 149, 251, 222, 174, 69, 197, 171, 176, 115, 67,
            144, 76, 135, 147, 21, 48, 196, 235, 169, 93, 34, 100, 63, 20, 128, 61, 191, 214, 161,
            240, 38, 228, 74, 250, 91, 185, 68, 243, 172, 203, 43, 174, 99, 230, 231, 239, 161, 78,
            148, 160, 170, 87, 200, 24, 220, 196, 53, 107, 22, 85, 59, 227, 237, 150, 83, 81, 41,
            2, 132,
        ];

        let uc_pk = UncompressedPublicKey::try_from(pk_bytes.as_ref()).unwrap();
        assert_eq!(&pk_bytes, &uc_pk.0.to_encoded_point(false).as_ref());
        let c_pk = AsymmetricPublicKey::<V3>::try_from(&uc_pk).unwrap();
        assert_eq!(&c_pk.as_bytes()[1..], &pk_bytes[1..49]);

        let round = UncompressedPublicKey::try_from(&c_pk).unwrap();

        assert_eq!(round.0.to_encoded_point(false).as_ref(), pk_bytes);
    }

    #[test]
    fn fuzzer_regression_2() {
        let data: [u8; 49] = [
            2, 0, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49,
            49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49, 49,
            49, 49, 49, 49, 49,
        ];

        if let Ok(compressed_pk) = AsymmetricPublicKey::<V3>::from(&data) {
            if let Ok(uncompressed) = UncompressedPublicKey::try_from(&compressed_pk) {
                assert_eq!(
                    AsymmetricPublicKey::<V3>::try_from(&uncompressed)
                        .unwrap()
                        .as_bytes(),
                    compressed_pk.as_bytes()
                );
            }
        }
    }

    #[test]
    fn fuzzer_regression_3() {
        let data: [u8; 49] = [
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        if let Ok(compressed_pk) = AsymmetricPublicKey::<V3>::from(&data) {
            if let Ok(uncompressed) = UncompressedPublicKey::try_from(&compressed_pk) {
                assert_eq!(
                    AsymmetricPublicKey::<V3>::try_from(&uncompressed)
                        .unwrap()
                        .as_bytes(),
                    compressed_pk.as_bytes()
                );
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod test_vectors {

    use super::*;
    use hex;
    use std::fs::File;
    use std::io::BufReader;

    use crate::common::tests::*;

    fn test_pk_conversion(pk: &AsymmetricPublicKey<V3>) {
        let uc_pk = UncompressedPublicKey::try_from(pk).unwrap();
        let c_pk: AsymmetricPublicKey<V3> = AsymmetricPublicKey::try_from(&uc_pk).unwrap();

        assert_eq!(
            pk.as_bytes(),
            c_pk.as_bytes(),
            "Failed to roundtrip conversion between compressed and uncompressed public key"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        // Values taken from 3-S-1
        let raw_sk = hex::decode("20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96").unwrap();
        let raw_pk = hex::decode("02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb").unwrap();

        let sk = AsymmetricSecretKey::<V3>::from(&raw_sk).unwrap();
        let pk = AsymmetricPublicKey::<V3>::from(&raw_pk).unwrap();
        let message = "this is a signed message";

        let token = UntrustedToken::<Public, V3>::try_from(
            &PublicToken::sign(&sk, message.as_bytes(), Some(b"footer"), Some(b"impl")).unwrap(),
        )
        .unwrap();
        assert!(PublicToken::verify(&pk, &token, Some(b"footer"), Some(b"impl")).is_ok());
    }

    fn test_public(test: &PasetoTest) {
        debug_assert!(test.public_key.is_some());
        debug_assert!(test.secret_key.is_some());

        let sk = AsymmetricSecretKey::<V3>::from(
            &hex::decode(test.secret_key.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        let pk = AsymmetricPublicKey::<V3>::from(
            &hex::decode(test.public_key.as_ref().unwrap()).unwrap(),
        )
        .unwrap();

        test_pk_conversion(&pk);

        let footer: Option<&[u8]> = if test.footer.as_bytes().is_empty() {
            None
        } else {
            Some(test.footer.as_bytes())
        };
        let implicit_assert = test.implicit_assertion.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            if let Ok(ut) = UntrustedToken::<Public, V3>::try_from(&test.token) {
                assert!(PublicToken::verify(&pk, &ut, footer, Some(implicit_assert)).is_err());
            }

            return;
        }

        let message = test.payload.as_ref().unwrap().as_str().unwrap();

        let actual =
            PublicToken::sign(&sk, message.as_bytes(), footer, Some(implicit_assert)).unwrap();
        let ut = UntrustedToken::<Public, V3>::try_from(&actual).unwrap();
        let trusted = PublicToken::verify(&pk, &ut, footer, Some(implicit_assert)).unwrap();
        assert_eq!(trusted.payload(), message);
        assert_eq!(trusted.footer(), test.footer.as_bytes());
        assert_eq!(trusted.header(), PublicToken::HEADER);
        assert_eq!(trusted.implicit_assert(), implicit_assert);

        let ut = UntrustedToken::<Public, V3>::try_from(&test.token).unwrap();
        let trusted = PublicToken::verify(&pk, &ut, footer, Some(implicit_assert)).unwrap();
        assert_eq!(trusted.payload(), message);
        assert_eq!(trusted.footer(), test.footer.as_bytes());
        assert_eq!(trusted.header(), PublicToken::HEADER);
        assert_eq!(trusted.implicit_assert(), implicit_assert);
    }

    #[test]
    fn run_test_vectors() {
        let path = "./test_vectors/v3.json";
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let tests: TestFile = serde_json::from_reader(reader).unwrap();

        for t in tests.tests {
            // v3.public
            if t.public_key.is_some() {
                test_public(&t);
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod test_wycheproof_point_compression {
    use super::*;
    use crate::keys::AsymmetricPublicKey;
    use alloc::string::String;
    use alloc::vec::Vec;
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;
    use std::fs::File;
    use std::io::BufReader;

    #[allow(dead_code)] // `notes` field
    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct WycheproofSecp384r1Tests {
        algorithm: String,
        generatorVersion: String,
        numberOfTests: u64,
        header: Vec<String>,
        #[serde(skip)]
        notes: Vec<String>, // Not a Vec<>, but we don't need this so skip it.
        schema: String,
        testGroups: Vec<Secp384r1TestGroup>,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct Secp384r1TestGroup {
        key: Secp384r1Key,
        keyDer: String,
        keyPem: String,
        sha: String,
        #[serde(rename(deserialize = "type"))]
        testType: String,
        tests: Vec<TestVector>,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct Secp384r1Key {
        curve: String,
        keySize: u64,
        #[serde(rename(deserialize = "type"))]
        keyType: String,
        uncompressed: String,
        wx: String,
        wy: String,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    pub(crate) struct TestVector {
        tcId: u64,
        comment: String,
        msg: String,
        sig: String,
        result: String,
        flags: Vec<String>,
    }

    fn wycheproof_point_compression(path: &str) {
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let tests: WycheproofSecp384r1Tests = serde_json::from_reader(reader).unwrap();

        for test_group in tests.testGroups.iter() {
            let uc_pk = UncompressedPublicKey::try_from(
                hex::decode(&test_group.key.uncompressed)
                    .unwrap()
                    .as_slice(),
            )
            .expect("Failed Wycheproof -> Uncompressed");

            let pk = AsymmetricPublicKey::<V3>::try_from(&uc_pk).unwrap();
            assert_eq!(
                hex::encode(
                    UncompressedPublicKey::try_from(&pk)
                        .unwrap()
                        .0
                        .to_encoded_point(false)
                        .as_ref()
                ),
                test_group.key.uncompressed,
                "Failed {:?}",
                &test_group.key.uncompressed
            );
        }
    }

    #[test]
    fn run_wycheproof_points() {
        wycheproof_point_compression(
            "./test_vectors/wycheproof/ecdsa_secp384r1_sha3_384_test.json",
        );
        wycheproof_point_compression("./test_vectors/wycheproof/ecdsa_secp384r1_sha384_test.json");
    }
}

#[cfg(test)]
mod test_tokens {
    use super::*;
    use crate::common::decode_b64;
    use crate::keys::{AsymmetricKeyPair, Generate};
    use crate::token::UntrustedToken;

    // 3-S-2 values
    const TEST_SK_BYTES: [u8; 48] = [
        32, 52, 118, 9, 96, 116, 119, 172, 168, 251, 251, 197, 230, 33, 132, 85, 243, 25, 150, 105,
        121, 46, 248, 180, 102, 250, 168, 123, 220, 103, 121, 129, 68, 200, 72, 221, 3, 102, 30,
        237, 90, 198, 36, 97, 52, 12, 234, 150,
    ];
    const TEST_PK_BYTES: [u8; 49] = [
        2, 251, 203, 124, 105, 238, 28, 96, 87, 155, 231, 163, 52, 19, 72, 120, 217, 197, 197, 191,
        53, 213, 82, 218, 182, 60, 1, 64, 57, 126, 209, 76, 239, 99, 125, 119, 32, 146, 92, 68,
        105, 158, 163, 14, 114, 135, 76, 114, 251,
    ];

    const MESSAGE: &str =
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const FOOTER: &str = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const VALID_PUBLIC_TOKEN: &str = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9";

    #[test]
    fn test_gen_keypair() {
        let kp = AsymmetricKeyPair::<V3>::generate().unwrap();

        let token = PublicToken::sign(&kp.secret, MESSAGE.as_bytes(), None, None).unwrap();

        let ut = UntrustedToken::<Public, V3>::try_from(&token).unwrap();
        assert!(PublicToken::verify(&kp.public, &ut, None, None).is_ok());
    }

    #[test]
    fn test_untrusted_token_usage() {
        // Public
        let kp = AsymmetricKeyPair::<V3>::generate().unwrap();
        let token = PublicToken::sign(
            &kp.secret,
            MESSAGE.as_bytes(),
            Some(FOOTER.as_bytes()),
            None,
        )
        .unwrap();

        let untrusted_token = UntrustedToken::<Public, V3>::try_from(token.as_str()).unwrap();
        assert!(PublicToken::verify(
            &kp.public,
            &untrusted_token,
            Some(untrusted_token.untrusted_footer()),
            None
        )
        .is_ok());
    }

    #[test]
    fn test_roundtrip_public() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        let token = PublicToken::sign(&test_sk, MESSAGE.as_bytes(), None, None).unwrap();
        let ut = UntrustedToken::<Public, V3>::try_from(&token).unwrap();

        assert!(PublicToken::verify(&test_pk, &ut, None, None).is_ok());
    }

    #[test]
    fn footer_logic() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";

        // We create a token with Some(footer) and with None
        let actual_some = UntrustedToken::<Public, V3>::try_from(
            &PublicToken::sign(&test_sk, message, Some(FOOTER.as_bytes()), None).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Public, V3>::try_from(
            &PublicToken::sign(&test_sk, message, None, None).unwrap(),
        )
        .unwrap();

        // token = Some(footer) = validate and compare
        // token = None(footer) = validate only

        // We should be able to validate with None if created with Some() (excludes constant-time
        // comparison with known value)
        assert!(PublicToken::verify(&test_pk, &actual_some, None, None).is_ok());
        // We should be able to validate with Some() if created with Some()
        assert!(PublicToken::verify(&test_pk, &actual_some, Some(FOOTER.as_bytes()), None).is_ok());
        // We should NOT be able to validate with Some() if created with None
        assert!(
            PublicToken::verify(&test_pk, &actual_none, Some(FOOTER.as_bytes()), None).is_err()
        );
    }

    #[test]
    fn implicit_none_some_empty_is_same() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
        let implicit = b"";

        let actual_some = UntrustedToken::<Public, V3>::try_from(
            &PublicToken::sign(&test_sk, message, None, Some(implicit)).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Public, V3>::try_from(
            &PublicToken::sign(&test_sk, message, None, None).unwrap(),
        )
        .unwrap();

        assert!(PublicToken::verify(&test_pk, &actual_none, None, Some(implicit)).is_ok());
        assert!(PublicToken::verify(&test_pk, &actual_some, None, None).is_ok());
    }

    #[test]
    // NOTE: See https://github.com/paseto-standard/paseto-spec/issues/17
    fn empty_payload() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();

        assert_eq!(
            PublicToken::sign(&test_sk, b"", None, None).unwrap_err(),
            Error::EmptyPayload
        );
    }

    #[test]
    fn err_on_modified_footer() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V3>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.replace("kid", "mid").as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_wrong_implicit_assert() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();
        assert!(PublicToken::verify(
            &test_pk,
            &UntrustedToken::<Public, V3>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
            Some(FOOTER.as_bytes()),
            None
        )
        .is_ok());
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V3>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.as_bytes()),
                Some(b"WRONG IMPLICIT")
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_footer_in_token_none_supplied() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V3>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(b""),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_no_footer_in_token_some_supplied() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        let split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        let invalid_public: String = format!(
            "{}.{}.{}",
            split_public[0], split_public[1], split_public[2]
        );

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V3>::try_from(&invalid_public).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_signature() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_sig = decode_b64(split_public[2]).unwrap();
        bad_sig.copy_within(0..32, 32);
        let tmp = encode_b64(bad_sig).unwrap();
        split_public[2] = &tmp;
        let invalid_public: String = format!(
            "{}.{}.{}.{}",
            split_public[0], split_public[1], split_public[2], split_public[3]
        );

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V3>::try_from(&invalid_public).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_invalid_public_secret_key() {
        let mut pk_bytes = [0u8; 49];
        pk_bytes[0] = 2;
        let bad_pk = AsymmetricPublicKey::<V3>::from(&pk_bytes).unwrap();

        assert_eq!(
            PublicToken::verify(
                &bad_pk,
                &UntrustedToken::<Public, V3>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }
}

#[cfg(test)]
mod test_keys {
    use super::*;
    use crate::keys::SymmetricKey;

    #[test]
    #[should_panic]
    fn test_v3_local_not_implemented() {
        assert!(SymmetricKey::<V3>::from(&[0u8; 32]).is_ok());
    }

    #[test]
    fn test_invalid_sizes() {
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
    }

    #[test]
    fn try_from_secret_to_public() {
        let kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        let pubv3 = AsymmetricPublicKey::<V3>::try_from(&kpv3.secret).unwrap();
        assert_eq!(pubv3.as_bytes(), kpv3.public.as_bytes());
        assert_eq!(pubv3, kpv3.public);
    }

    #[test]
    fn test_trait_impls() {
        let debug = format!("{:?}", AsymmetricKeyPair::<V3>::generate().unwrap().secret);
        assert_eq!(debug, "AsymmetricSecretKey {***OMITTED***}");

        let randomv = AsymmetricKeyPair::<V3>::generate().unwrap();
        let randomv2 = AsymmetricKeyPair::<V3>::generate().unwrap();
        assert_ne!(randomv.secret, randomv2.secret);
    }

    #[test]
    fn test_invalid_pk() {
        let uc_badlen = [0u8; 96];
        let mut uc_badtag = [0u8; 97];
        uc_badtag[0] = 0x02;

        assert!(UncompressedPublicKey::try_from(uc_badlen.as_ref()).is_err());
        assert!(UncompressedPublicKey::try_from(uc_badtag.as_ref()).is_err());

        let mut kpv3 = AsymmetricKeyPair::<V3>::generate().unwrap();
        kpv3.public.bytes[0] = 0x04;
        assert!(UncompressedPublicKey::try_from(&kpv3.public).is_err());
    }

    #[test]
    fn test_clone() {
        let kp = AsymmetricKeyPair::<V3>::generate().unwrap();
        assert_eq!(kp.secret, kp.secret.clone());
        assert_eq!(kp.public, kp.public.clone());
    }
}
