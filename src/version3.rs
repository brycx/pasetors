#![cfg_attr(docsrs, doc(cfg(feature = "v3")))]

//!
//! This is an implementation of the [version 3 specification of PASETO](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign).
//!
//! The following points apply to this implementation, in regards to the specification:
//! - PASETO requires the use of compressed public keys. If these are not readily supported in a given
//! setting, [UncompressedPublicKey] and [AsymmetricPublicKey<V3>] conversions can be used to obtain
//! the compressed form.
//! - PASETO recommends use of deterministic nonces (RFC-6979), but this is not supported by the P-384
//! implementation provided by [*ring*](https://crates.io/crates/ring). This may change in the future.
//! - Hedged signatures, according to the PASETO spec, are not used.
//!
//! [AsymmetricPublicKey<V3>]: crate::keys::AsymmetricPublicKey
//! [UncompressedPublicKey]: crate::version3::UncompressedPublicKey

use crate::common::{decode_b64, encode_b64, validate_format_footer};
use crate::errors::Error;
use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, V3};
use crate::pae;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING};

/// P384 prime in big-endian: 2^384 - 2^128 - 2^96 + 2^32 - 1.
const P: [u8; 48] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 0, 0, 0,
    0, 0, 0, 0, 0, 255, 255, 255, 255,
];

/// (P+1)/4 in big-endian.
const P_PLUS_ONE_DIV_FOUR: [u8; 48] = [
    63, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 191, 255, 255, 255, 192, 0, 0,
    0, 0, 0, 0, 0, 64, 0, 0, 0,
];

/// (P-1)/2 in big-endian.
const P_MINUS_ONE_DIV_TWO: [u8; 48] = [
    127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127, 255, 255, 255, 128, 0, 0,
    0, 0, 0, 0, 0, 127, 255, 255, 255,
];

/// P384 constant B.
const B: [u8; 48] = [
    179, 49, 47, 167, 226, 62, 231, 228, 152, 142, 5, 107, 227, 248, 45, 25, 24, 29, 156, 110, 254,
    129, 65, 18, 3, 20, 8, 143, 80, 19, 135, 90, 198, 86, 57, 141, 138, 46, 209, 157, 42, 133, 200,
    237, 211, 236, 42, 239,
];

/// The constant A (-3) mod P, equivalent to P-3.
const A_MOD_P: [u8; 48] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 0, 0, 0,
    0, 0, 0, 0, 0, 255, 255, 255, 252,
];

/// This struct represents a uncompressed public key for P384, encoded in big-endian using:
/// Octet-String-to-Elliptic-Curve-Point algorithm in SEC 1: Elliptic Curve Cryptography, Version 2.0.
///
/// Format: [0x04, x, y]
///
/// This is provided to be able to convert uncompressed keys to compressed ones, as compressed is
/// required by PASETO and what an `AsymmetricPublicKey<V3>` represents.
pub struct UncompressedPublicKey(pub [u8; 97]);

impl TryFrom<&[u8]> for UncompressedPublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let pk: [u8; 97] = value.try_into().map_err(|_| Error::Key)?;
        if pk[0] != 4 {
            return Err(Error::Key);
        }

        Ok(Self(pk))
    }
}

/// Compute the Legendre symbol for `a`, given prime [`P`].
///
/// Ref: <https://en.wikipedia.org/wiki/Legendre_symbol>
fn legendre_symbol(a: &BigUint) -> i32 {
    let p = BigUint::from_bytes_be(&P);
    debug_assert_eq!(&p % BigUint::from(2u32), BigUint::one()); // Ensure odd prime

    let one = BigUint::one();
    let zero = BigUint::zero();
    let r = a.modpow(&BigUint::from_bytes_be(&P_MINUS_ONE_DIV_TWO), &p);

    if r == one {
        1
    } else if r == zero {
        0
    } else {
        -1
    }
}

impl TryFrom<&AsymmetricPublicKey<V3>> for UncompressedPublicKey {
    type Error = Error;

    fn try_from(value: &AsymmetricPublicKey<V3>) -> Result<Self, Self::Error> {
        debug_assert_eq!(value.bytes.len(), 49);
        debug_assert_eq!(
            BigUint::from_bytes_be(&P) % BigUint::from(4u32),
            BigUint::from(3u32)
        );

        let prime = BigUint::from_bytes_be(&P);
        let p_ident = BigUint::from_bytes_be(&P_PLUS_ONE_DIV_FOUR);
        let a = BigUint::from_bytes_be(&A_MOD_P);
        let b = BigUint::from_bytes_be(&B);
        let sign_y = BigUint::from(&value.bytes[0] - 2);
        let x = BigUint::from_bytes_be(&value.bytes[1..]);
        if x >= prime {
            return Err(Error::PublicKeyConversion);
        }

        // Pre-computed -3 so no sub op.
        let y2 = x.pow(3u32) + (&a * &x) + b;
        if legendre_symbol(&y2) != 1 {
            return Err(Error::PublicKeyConversion);
        }

        // Because P mod 4 === 3, we can get the square root by taking (y^{2})^{(P+1)/4}.
        let mut y = y2.modpow(&p_ident, &prime);

        if &y % 2u32 != sign_y {
            y = prime - y;
        }

        let mut ret = [0u8; 97];
        ret[0] = 0x04;

        let mut x_start: usize = 1; // 0-indexed
        let mut y_start: usize = 49; // 0-indexed
        let xbytes = x.to_bytes_be();
        let ybytes = y.to_bytes_be();

        // Leading zeroes can have been dropped in some cases, so we check here if we should
        // keep any, based on the BE repr of the integer.
        if xbytes.len() != 48 {
            debug_assert!(xbytes.len() < 48);
            let diff = 48 - xbytes.len();
            x_start += diff as usize;
        }
        if ybytes.len() != 48 {
            debug_assert!(ybytes.len() < 48);
            let diff = 48 - ybytes.len();
            y_start += diff as usize;
        }

        debug_assert!((1..=49).contains(&x_start));
        debug_assert!((49..=97).contains(&y_start));

        ret[x_start..xbytes.len() + x_start].copy_from_slice(&xbytes);
        ret[y_start..ybytes.len() + y_start].copy_from_slice(&ybytes);

        Ok(UncompressedPublicKey(ret))
    }
}

impl TryFrom<&UncompressedPublicKey> for AsymmetricPublicKey<V3> {
    type Error = Error;

    fn try_from(value: &UncompressedPublicKey) -> Result<Self, Self::Error> {
        let mut compressed = [0u8; 49];
        compressed[0] = 0x02;
        let tmp: i8 = (BigUint::from_bytes_be(&value.0[49..]) % 2u32)
            .try_into()
            .unwrap();
        compressed[0] += tmp as u8; // 2 if even, 3 if odd
        compressed[1..].copy_from_slice(&value.0[1..49]);

        Ok(Self {
            bytes: compressed.to_vec(),
            phantom: PhantomData,
        })
    }
}

/// PASETO v3 public tokens.
pub struct PublicToken;

impl PublicToken {
    /// The header and purpose for the public token: `v3.public.`.
    pub const HEADER: &'static str = "v3.public.";

    /// Length of a v3 signature.
    const SIGNATURE_LEN: usize = 96;

    /// Create a public token.
    ///
    /// The `secret_key` and `public_key` **must** be in big-endian.
    ///
    /// ### Error:
    /// - *ring* calls `generate()` internally, when creating the signature. Thus, it is possible
    /// for [`Error::Signing`] to represent a failed call to the CSPRNG.
    pub fn sign(
        secret_key: &AsymmetricSecretKey<V3>,
        public_key: &AsymmetricPublicKey<V3>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        use ring::rand;

        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let uc_pk = UncompressedPublicKey::try_from(public_key)?;
        let kp = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            secret_key.as_bytes(),
            &uc_pk.0,
        )
        .map_err(|_| Error::Key)?;

        let csprng = rand::SystemRandom::new();

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);
        let m2 = pae::pae(&[
            public_key.as_bytes(),
            Self::HEADER.as_bytes(),
            message,
            f,
            i,
        ])?;

        let sig = kp.sign(&csprng, m2.as_ref()).map_err(|_| Error::Signing)?;
        debug_assert_eq!(sig.as_ref().len(), Self::SIGNATURE_LEN);

        let mut m_sig: Vec<u8> = Vec::from(message);
        m_sig.extend_from_slice(sig.as_ref());

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
    /// ### Security:
    /// - `public_key` is not verified by constructing `AsymmetricPublicKey<V3>`, but first
    /// when the signature of the token is verified as well. Therefor, [`Error::TokenValidation`]
    /// returned here can both mean an invalid public key and an invalid signature.
    pub fn verify(
        public_key: &AsymmetricPublicKey<V3>,
        token: &str,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<(), Error> {
        use ring::signature;

        if token.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);

        let parts_split = validate_format_footer(Self::HEADER, token, f)?;
        let sm = decode_b64(parts_split[2])?;
        if sm.len() < Self::SIGNATURE_LEN {
            return Err(Error::TokenFormat);
        }

        let m = sm[..(sm.len() - Self::SIGNATURE_LEN)].as_ref();
        let s = sm[m.len()..m.len() + Self::SIGNATURE_LEN].as_ref();

        let m2 = pae::pae(&[public_key.as_bytes(), Self::HEADER.as_bytes(), m, f, i])?;

        let uc_pk = UncompressedPublicKey::try_from(public_key)?;
        // NOTE: `unparsed_pk` is only validated once we verify the signature.
        let unparsed_pk = signature::UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &uc_pk.0);

        debug_assert!(s.len() == Self::SIGNATURE_LEN);
        // If the below fails, it is an invalid signature or invalid public key.
        unparsed_pk
            .verify(m2.as_ref(), s)
            .map_err(|_| Error::TokenValidation)
    }
}

#[cfg(test)]
mod test_regression {
    use crate::keys::{AsymmetricPublicKey, V3};
    use crate::version3::UncompressedPublicKey;
    use std::convert::TryFrom;

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
        assert_eq!(&pk_bytes, &uc_pk.0);
        let c_pk = AsymmetricPublicKey::<V3>::try_from(&uc_pk).unwrap();
        assert_eq!(&c_pk.as_bytes()[1..], &pk_bytes[1..49]);

        let round = UncompressedPublicKey::try_from(&c_pk).unwrap();

        assert_eq!(round.0, pk_bytes);
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

    use hex;

    use super::*;
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
    /// These are not covered during test-vector runs, because of the use of CSPRNG for k-value generation
    /// within *ring*.
    fn sign_verify_roundtrip() {
        // Values taken from 3-S-1
        let raw_sk = hex::decode("20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96").unwrap();
        let raw_pk = hex::decode("02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb").unwrap();

        let sk = AsymmetricSecretKey::<V3>::from(&raw_sk).unwrap();
        let pk = AsymmetricPublicKey::<V3>::from(&raw_pk).unwrap();
        let message = "this is a signed message";

        let token = PublicToken::sign(&sk, &pk, message.as_bytes(), Some(b"footer"), Some(b"impl"))
            .unwrap();
        PublicToken::sign(&sk, &pk, message.as_bytes(), Some(b"footer"), Some(b"impl")).unwrap();
        assert!(PublicToken::verify(&pk, &token, Some(b"footer"), Some(b"impl")).is_ok());
    }

    fn test_public(test: &PasetoTest) {
        debug_assert!(test.public_key.is_some());
        debug_assert!(test.secret_key.is_some());
        let pk = AsymmetricPublicKey::<V3>::from(
            &hex::decode(test.public_key.as_ref().unwrap()).unwrap(),
        )
        .unwrap();

        test_pk_conversion(&pk);

        let footer = test.footer.as_bytes();
        let implicit_assert = test.implicit_assertion.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            assert!(
                PublicToken::verify(&pk, &test.token, Some(footer), Some(implicit_assert)).is_err()
            );

            return;
        }

        // We do not have support for deterministic nonces, so we cannot reproduce a signature
        // because ring uses CSPRNG for k-value. Therefor, we can only validate (compared to V2/V4 tests).
        assert!(
            PublicToken::verify(&pk, &test.token, Some(footer), Some(implicit_assert)).is_ok(),
            "Failed {:?}",
            test.name
        );
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
    use crate::keys::{AsymmetricPublicKey, V3};
    use crate::version3::UncompressedPublicKey;
    use alloc::string::String;
    use alloc::vec::Vec;
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
                hex::encode(UncompressedPublicKey::try_from(&pk).unwrap().0),
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
mod tests {
    use super::*;

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

    const MESSAGE: &'static str =
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const FOOTER: &'static str = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const VALID_PUBLIC_TOKEN: &'static str = "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9";

    #[test]
    fn test_roundtrip_public() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        let token = PublicToken::sign(&test_sk, &test_pk, MESSAGE.as_bytes(), None, None).unwrap();
        assert!(PublicToken::verify(&test_pk, &token, None, None).is_ok());
    }

    #[test]
    fn footer_none_some_empty_is_same() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
        let footer = b"";

        let actual_some =
            PublicToken::sign(&test_sk, &test_pk, message, Some(footer), None).unwrap();
        let actual_none = PublicToken::sign(&test_sk, &test_pk, message, None, None).unwrap();

        assert!(PublicToken::verify(&test_pk, &actual_none, Some(footer), None).is_ok());
        assert!(PublicToken::verify(&test_pk, &actual_some, None, None).is_ok());
    }

    #[test]
    fn implicit_none_some_empty_is_same() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
        let implicit = b"";

        let actual_some =
            PublicToken::sign(&test_sk, &test_pk, message, None, Some(implicit)).unwrap();
        let actual_none = PublicToken::sign(&test_sk, &test_pk, message, None, None).unwrap();

        assert!(PublicToken::verify(&test_pk, &actual_none, None, Some(implicit)).is_ok());
        assert!(PublicToken::verify(&test_pk, &actual_some, None, None).is_ok());
    }

    #[test]
    // NOTE: See https://github.com/paseto-standard/paseto-spec/issues/17
    fn empty_payload() {
        let test_sk = AsymmetricSecretKey::<V3>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        assert_eq!(
            PublicToken::sign(&test_sk, &test_pk, b"", None, None).unwrap_err(),
            Error::EmptyPayload
        );
        assert_eq!(
            PublicToken::verify(&test_pk, "", None, None).unwrap_err(),
            Error::EmptyPayload
        );
    }

    #[test]
    fn err_on_modified_header() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("v3", "v2"),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("v3", ""),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    fn err_on_modified_purpose() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("public", "local"),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenFormat
        );
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("public", ""),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    // NOTE: Missing but created with one
    fn err_on_missing_payload() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        split_public[2] = "";
        let invalid_public: String = split_public.iter().map(|x| *x).collect();

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    fn err_on_extra_after_footer() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        split_public.push(".shouldNotBeHere");
        let invalid_public: String = split_public.iter().map(|x| *x).collect();

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Error::TokenFormat
        );
    }

    #[test]
    fn err_on_modified_footer() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN,
                Some(&FOOTER.replace("kid", "mid").as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_wrong_implicit_assert() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();
        assert!(
            PublicToken::verify(&test_pk, &VALID_PUBLIC_TOKEN, Some(FOOTER.as_bytes()), None)
                .is_ok()
        );
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN,
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
            PublicToken::verify(&test_pk, &VALID_PUBLIC_TOKEN, Some(b""), None).unwrap_err(),
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
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_signature() {
        let test_pk = AsymmetricPublicKey::<V3>::from(&TEST_PK_BYTES).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_sig = Vec::from(decode_b64(split_public[2]).unwrap());
        bad_sig.copy_within(0..32, 32);
        let tmp = encode_b64(bad_sig).unwrap();
        split_public[2] = &tmp;
        let invalid_public: String = format!(
            "{}.{}.{}.{}",
            split_public[0], split_public[1], split_public[2], split_public[3]
        );

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes()), None)
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
            PublicToken::verify(&bad_pk, VALID_PUBLIC_TOKEN, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Error::TokenValidation
        );
    }
}
