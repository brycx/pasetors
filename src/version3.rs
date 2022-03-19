use crate::common::{decode_b64, encode_b64, validate_format_footer};
use crate::errors::Error;
use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, V3};
use crate::pae;
use core::convert::{TryFrom, TryInto};
use core::marker::PhantomData;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};
use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING};

/// This struct represents a uncompressed public key for P384, encoded in big-endian using:
/// Octet-String-to-Elliptic-Curve-Point algorithm in SEC 1: Elliptic Curve Cryptography, Version 2.0.
///
/// Format: [0x04, x, y]
///
/// This is provided to be able to convert uncompressed keys to compressed ones, as compressed is
/// required by PASETO and what an `AsymmetricPublicKey<V3>` represents.
pub struct UncompressedPublicKey([u8; 97]);

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

// TODO: Tonelli-Shanks?
impl TryFrom<&AsymmetricPublicKey<V3>> for UncompressedPublicKey {
    type Error = Error;

    fn try_from(value: &AsymmetricPublicKey<V3>) -> Result<Self, Self::Error> {
        debug_assert_eq!(value.bytes.len(), 49);

        let two = BigUint::from_u8(2).unwrap();
        let prime =
            two.pow(384u32) - two.pow(128u32) - two.pow(96u32) + two.pow(32) - BigUint::one();
        let p_ident = (&prime + BigUint::one()) / BigUint::from(4u32);
        let b = BigUint::from_bytes_be(&[
            0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8,
            0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f,
            0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85,
            0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
        ]);
        let sign_y = BigUint::from(&value.bytes[0] - 2);

        let x = BigUint::from_bytes_be(&value.bytes[1..]);
        let mut y2 = x.pow(3u32) - BigUint::from(3u32) * &x + b;
        y2 = y2.modpow(&p_ident, &prime);

        if &y2 % 2u32 != sign_y {
            y2 = prime - y2;
        }

        let mut ret = [0u8; 97];
        ret[0] = 4;
        ret[1..49].copy_from_slice(&x.to_bytes_be());
        ret[49..].copy_from_slice(&y2.to_bytes_be());

        Ok(UncompressedPublicKey(ret))
    }
}

impl TryFrom<&UncompressedPublicKey> for AsymmetricPublicKey<V3> {
    type Error = Error;

    fn try_from(value: &UncompressedPublicKey) -> Result<Self, Self::Error> {
        let mut compressed = [0u8; 49];
        compressed[0] = 0x02;
        // TODO: Maybe we should check sign without making a BigUint here
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
        // TODO: Check on what conditions we error out here and document
        let kp = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            secret_key.as_bytes(),
            &uc_pk.0,
        )
        .map_err(|_| Error::Key)?;

        // TODO: Check on what conditions we panic out here and document
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
        // TODO: Check on what conditions we error out here and document
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
