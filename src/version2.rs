#![cfg_attr(docsrs, doc(cfg(feature = "v2")))]

use crate::common::{encode_b64, validate_footer_untrusted_token};
use crate::errors::Error;
use crate::keys::{
    AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate, SymmetricKey,
};
use crate::pae;
use crate::token::{Local, Public, TrustedToken, UntrustedToken};
use crate::version::private::Version;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::marker::PhantomData;
use ed25519_compact::{KeyPair, PublicKey, SecretKey as SigningKey, Seed, Signature};
use orion::hazardous::aead::xchacha20poly1305::*;
use orion::hazardous::mac::blake2b;
use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;
use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;
use subtle::ConstantTimeEq;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Version 2 of the PASETO spec.
pub struct V2;

impl Version for V2 {
    const LOCAL_KEY: usize = 32;
    const SECRET_KEY: usize = 32 + Self::PUBLIC_KEY; // Seed || PK
    const PUBLIC_KEY: usize = 32;
    const PUBLIC_SIG: usize = 64;
    const LOCAL_NONCE: usize = 24;
    const LOCAL_TAG: usize = 16;
    const PUBLIC_HEADER: &'static str = "v2.public.";
    const LOCAL_HEADER: &'static str = "v2.local.";
    #[cfg(feature = "paserk")]
    const PASERK_ID: usize = 44;

    fn validate_local_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::LOCAL_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::SECRET_KEY {
            return Err(Error::Key);
        }

        let seed = Seed::from_slice(&key_bytes[..32]).map_err(|_| Error::Key)?;
        let kp = KeyPair::from_seed(seed);

        if !bool::from(kp.pk.as_slice().ct_eq(&key_bytes[32..])) {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::PUBLIC_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }
}

impl TryFrom<&AsymmetricSecretKey<V2>> for AsymmetricPublicKey<V2> {
    type Error = Error;

    fn try_from(value: &AsymmetricSecretKey<V2>) -> Result<Self, Self::Error> {
        AsymmetricPublicKey::<V2>::from(&value.as_bytes()[32..])
    }
}

impl Generate<AsymmetricKeyPair<V2>, V2> for AsymmetricKeyPair<V2> {
    fn generate() -> Result<AsymmetricKeyPair<V2>, Error> {
        let key_pair = KeyPair::generate();

        let secret = AsymmetricSecretKey::<V2>::from(key_pair.sk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;
        let public = AsymmetricPublicKey::<V2>::from(key_pair.pk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;

        Ok(Self { public, secret })
    }
}

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

/// PASETO v2 public tokens.
pub struct PublicToken;

impl PublicToken {
    /// The header and purpose for the public token: `v2.public.`.
    pub const HEADER: &'static str = "v2.public.";

    /// Create a public token.
    pub fn sign(
        secret_key: &AsymmetricSecretKey<V2>,
        message: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let sk = SigningKey::from_slice(secret_key.as_bytes()).map_err(|_| Error::Key)?;
        let f = footer.unwrap_or(&[]);
        let m2 = pae::pae(&[Self::HEADER.as_bytes(), message, f])?;
        let sig = sk.sign(m2, None);

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
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn verify(
        public_key: &AsymmetricPublicKey<V2>,
        token: &UntrustedToken<Public, V2>,
        footer: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let sm = token.untrusted_message();
        let m = token.untrusted_payload();
        let s = sm[m.len()..m.len() + V2::PUBLIC_SIG].as_ref();

        let m2 = pae::pae(&[Self::HEADER.as_bytes(), m, f])?;
        let pk: PublicKey = PublicKey::from_slice(public_key.as_bytes()).map_err(|_| Error::Key)?;

        debug_assert!(s.len() == V2::PUBLIC_SIG);
        // If the below fails, it is an invalid signature.
        let sig = Signature::from_slice(s).map_err(|_| Error::TokenValidation)?;

        if pk.verify(m2, &sig).is_ok() {
            TrustedToken::_new(Self::HEADER, m, f, &[])
        } else {
            Err(Error::TokenValidation)
        }
    }
}

/// PASETO v2 local tokens.
pub struct LocalToken;

impl LocalToken {
    /// The header and purpose for the local token: `v2.local.`.
    pub const HEADER: &'static str = "v2.local.";

    /// Encrypt and authenticate a message using nonce_key_bytes to derive a nonce
    /// using BLAKE2b.
    pub(crate) fn encrypt_with_derived_nonce(
        secret_key: &SymmetricKey<V2>,
        nonce_key_bytes: &[u8],
        message: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<String, Error> {
        debug_assert!(nonce_key_bytes.len() == XCHACHA_NONCESIZE);

        // Safe unwrap()s due to lengths.
        let nonce_key = blake2b::SecretKey::from_slice(nonce_key_bytes).unwrap();
        let mut blake2b = blake2b::Blake2b::new(&nonce_key, XCHACHA_NONCESIZE).unwrap();
        blake2b.update(message.as_ref()).unwrap();
        let nonce = Nonce::from_slice(blake2b.finalize().unwrap().unprotected_as_bytes()).unwrap();

        let f = footer.unwrap_or(&[]);

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), nonce.as_ref(), f])?;
        let mut out = vec![0u8; message.len() + POLY1305_OUTSIZE + nonce.len()];
        let sk = match SecretKey::from_slice(secret_key.as_bytes()) {
            Ok(val) => val,
            Err(orion::errors::UnknownCryptoError) => return Err(Error::Key),
        };

        match seal(
            &sk,
            &nonce,
            message,
            Some(&pre_auth),
            &mut out[nonce.len()..],
        ) {
            Ok(()) => (),
            Err(orion::errors::UnknownCryptoError) => return Err(Error::Encryption),
        }

        out[..nonce.len()].copy_from_slice(nonce.as_ref());
        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(out)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Create a local token.
    pub fn encrypt(
        secret_key: &SymmetricKey<V2>,
        message: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let mut rng_bytes = [0u8; XCHACHA_NONCESIZE];
        getrandom::getrandom(&mut rng_bytes)?;

        Self::encrypt_with_derived_nonce(secret_key, &rng_bytes, message, footer)
    }

    /// Verify and decrypt a local token.
    ///
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn decrypt(
        secret_key: &SymmetricKey<V2>,
        token: &UntrustedToken<Local, V2>,
        footer: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let nc = token.untrusted_message();
        let n = nc[..XCHACHA_NONCESIZE].as_ref();
        let c = nc[n.len()..].as_ref();

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), n, f])?;
        let mut out = vec![0u8; c.len() - POLY1305_OUTSIZE];

        let sk = match SecretKey::from_slice(secret_key.as_bytes()) {
            Ok(val) => val,
            Err(orion::errors::UnknownCryptoError) => return Err(Error::Key),
        };

        match open(
            &sk,
            &Nonce::from_slice(n).unwrap(),
            c,
            Some(pre_auth.as_ref()),
            &mut out,
        ) {
            Ok(()) => TrustedToken::_new(Self::HEADER, &out, f, &[]),
            Err(orion::errors::UnknownCryptoError) => Err(Error::TokenValidation),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod test_vectors {

    use hex;

    use super::*;
    use core::convert::TryFrom;
    use std::fs::File;
    use std::io::BufReader;

    use crate::claims::Claims;
    use crate::common::tests::*;

    fn test_local(test: &PasetoTest) {
        debug_assert!(test.nonce.is_some());
        debug_assert!(test.key.is_some());

        let sk =
            SymmetricKey::<V2>::from(&hex::decode(test.key.as_ref().unwrap()).unwrap()).unwrap();

        let nonce = hex::decode(test.nonce.as_ref().unwrap()).unwrap();
        let footer: Option<&[u8]> = if test.footer.as_bytes().is_empty() {
            None
        } else {
            Some(test.footer.as_bytes())
        };

        // payload is null when we expect failure
        if test.expect_fail {
            if let Ok(ut) = UntrustedToken::<Local, V2>::try_from(&test.token) {
                assert!(LocalToken::decrypt(&sk, &ut, footer).is_err());
            }

            return;
        }

        let message = test.payload.as_ref().unwrap().as_str().unwrap();

        let actual =
            LocalToken::encrypt_with_derived_nonce(&sk, &nonce, message.as_bytes(), footer)
                .unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);

        let ut = UntrustedToken::<Local, V2>::try_from(&test.token).unwrap();
        let trusted = LocalToken::decrypt(&sk, &ut, footer).unwrap();
        assert_eq!(trusted.payload(), message, "Failed {:?}", test.name);
        assert_eq!(trusted.footer(), test.footer.as_bytes());
        assert_eq!(trusted.header(), LocalToken::HEADER);
        assert!(trusted.implicit_assert().is_empty());

        let parsed_claims = Claims::from_bytes(trusted.payload().as_bytes()).unwrap();
        let test_vector_claims = serde_json::from_str::<Payload>(message).unwrap();

        assert_eq!(
            parsed_claims.get_claim("data").unwrap().as_str().unwrap(),
            test_vector_claims.data,
        );
        assert_eq!(
            parsed_claims.get_claim("exp").unwrap().as_str().unwrap(),
            test_vector_claims.exp,
        );
    }

    fn test_public(test: &PasetoTest) {
        debug_assert!(test.public_key.is_some());
        debug_assert!(test.secret_key.is_some());

        let sk = AsymmetricSecretKey::<V2>::from(
            &hex::decode(test.secret_key.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        let pk = AsymmetricPublicKey::<V2>::from(
            &hex::decode(test.public_key.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        let footer: Option<&[u8]> = if test.footer.as_bytes().is_empty() {
            None
        } else {
            Some(test.footer.as_bytes())
        };

        // payload is null when we expect failure
        if test.expect_fail {
            if let Ok(ut) = UntrustedToken::<Public, V2>::try_from(&test.token) {
                assert!(PublicToken::verify(&pk, &ut, footer).is_err());
            }

            return;
        }

        let message = test.payload.as_ref().unwrap().as_str().unwrap();

        let actual = PublicToken::sign(&sk, message.as_bytes(), footer).unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);
        let ut = UntrustedToken::<Public, V2>::try_from(&test.token).unwrap();

        let trusted = PublicToken::verify(&pk, &ut, footer).unwrap();
        assert_eq!(trusted.payload(), message);
        assert_eq!(trusted.footer(), test.footer.as_bytes());
        assert_eq!(trusted.header(), PublicToken::HEADER);
        assert!(trusted.implicit_assert().is_empty());
    }

    #[test]
    fn run_test_vectors() {
        let path = "./test_vectors/v2.json";
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let tests: TestFile = serde_json::from_reader(reader).unwrap();

        for t in tests.tests {
            // v2.public
            if t.public_key.is_some() {
                test_public(&t);
            }
            // v2.local
            if t.nonce.is_some() {
                test_local(&t);
            }
        }
    }
}

#[cfg(test)]
mod test_tokens {
    use super::*;
    use crate::common::decode_b64;
    use crate::keys::{AsymmetricKeyPair, Generate};
    use crate::token::UntrustedToken;
    use core::convert::TryFrom;

    const TEST_LOCAL_SK_BYTES: [u8; 32] = [
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
        130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    ];

    pub(crate) const TEST_SK_BYTES: [u8; 64] = [
        180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125,
        159, 133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116, 30, 185, 219, 187, 188, 4, 124, 3,
        253, 112, 96, 78, 0, 113, 240, 152, 126, 22, 178, 139, 117, 114, 37, 193, 31, 0, 65, 93,
        14, 32, 177, 162,
    ];

    const TEST_PK_BYTES: [u8; 32] = [
        30, 185, 219, 187, 188, 4, 124, 3, 253, 112, 96, 78, 0, 113, 240, 152, 126, 22, 178, 139,
        117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177, 162,
    ];

    const MESSAGE: &str =
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
    const FOOTER: &str = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const VALID_PUBLIC_TOKEN: &str = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const VALID_LOCAL_TOKEN: &str = "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    #[test]
    fn test_gen_keypair() {
        let kp = AsymmetricKeyPair::<V2>::generate().unwrap();

        let token = PublicToken::sign(&kp.secret, MESSAGE.as_bytes(), None).unwrap();

        let ut = UntrustedToken::<Public, V2>::try_from(&token).unwrap();
        assert!(PublicToken::verify(&kp.public, &ut, None).is_ok());
    }

    #[test]
    fn test_untrusted_token_usage() {
        // Local
        let sk = SymmetricKey::<V2>::generate().unwrap();
        let token = LocalToken::encrypt(&sk, MESSAGE.as_bytes(), Some(FOOTER.as_bytes())).unwrap();

        let untrusted_token = UntrustedToken::<Local, V2>::try_from(token.as_str()).unwrap();
        let _ = LocalToken::decrypt(
            &sk,
            &untrusted_token,
            Some(untrusted_token.untrusted_footer()),
        )
        .unwrap();

        // Public
        let kp = AsymmetricKeyPair::<V2>::generate().unwrap();
        let token =
            PublicToken::sign(&kp.secret, MESSAGE.as_bytes(), Some(FOOTER.as_bytes())).unwrap();

        let untrusted_token = UntrustedToken::<Public, V2>::try_from(token.as_str()).unwrap();
        assert!(PublicToken::verify(&kp.public, &untrusted_token, Some(FOOTER.as_bytes())).is_ok());
    }

    #[test]
    fn test_roundtrip_local() {
        let sk = SymmetricKey::<V2>::generate().unwrap();
        let message = "token payload";

        let token = LocalToken::encrypt(&sk, message.as_bytes(), None).unwrap();
        let ut = UntrustedToken::<Local, V2>::try_from(&token).unwrap();
        let trusted_token = LocalToken::decrypt(&sk, &ut, None).unwrap();

        assert_eq!(trusted_token.payload(), message);
    }

    #[test]
    fn test_roundtrip_public() {
        let test_sk = AsymmetricSecretKey::<V2>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V2>::from(&TEST_PK_BYTES).unwrap();

        let token = PublicToken::sign(&test_sk, MESSAGE.as_bytes(), None).unwrap();
        let ut = UntrustedToken::<Public, V2>::try_from(&token).unwrap();

        assert!(PublicToken::verify(&test_pk, &ut, None).is_ok());
    }

    #[test]
    fn footer_logic() {
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();
        let test_sk = AsymmetricSecretKey::<V2>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V2>::from(&TEST_PK_BYTES).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";

        // We create a token with Some(footer) and with None
        let actual_some = UntrustedToken::<Public, V2>::try_from(
            &PublicToken::sign(&test_sk, message, Some(FOOTER.as_bytes())).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Public, V2>::try_from(
            &PublicToken::sign(&test_sk, message, None).unwrap(),
        )
        .unwrap();

        // token = Some(footer) = validate and compare
        // token = None(footer) = validate only

        // We should be able to validate with None if created with Some() (excludes constant-time
        // comparison with known value)
        assert!(PublicToken::verify(&test_pk, &actual_some, None).is_ok());
        // We should be able to validate with Some() if created with Some()
        assert!(PublicToken::verify(&test_pk, &actual_some, Some(FOOTER.as_bytes())).is_ok());
        // We should NOT be able to validate with Some() if created with None
        assert!(PublicToken::verify(&test_pk, &actual_none, Some(FOOTER.as_bytes())).is_err());

        let actual_some = UntrustedToken::<Local, V2>::try_from(
            &LocalToken::encrypt(&test_local_sk, message, Some(FOOTER.as_bytes())).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Local, V2>::try_from(
            &LocalToken::encrypt(&test_local_sk, message, None).unwrap(),
        )
        .unwrap();

        // They don't equal because the nonce is random. So we only check decryption.
        assert!(LocalToken::decrypt(&test_local_sk, &actual_some, None).is_ok());
        assert!(LocalToken::decrypt(&test_local_sk, &actual_some, Some(FOOTER.as_bytes())).is_ok());
        assert!(
            LocalToken::decrypt(&test_local_sk, &actual_none, Some(FOOTER.as_bytes())).is_err()
        );
    }

    #[test]
    // NOTE: See https://github.com/paseto-standard/paseto-spec/issues/17
    fn empty_payload() {
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();
        let test_sk = AsymmetricSecretKey::<V2>::from(&TEST_SK_BYTES).unwrap();

        assert_eq!(
            PublicToken::sign(&test_sk, b"", None).unwrap_err(),
            Error::EmptyPayload
        );
        assert_eq!(
            LocalToken::encrypt(&test_local_sk, b"", None).unwrap_err(),
            Error::EmptyPayload
        );
    }

    #[test]
    fn err_on_modified_footer() {
        let test_pk = AsymmetricPublicKey::<V2>::from(&TEST_PK_BYTES).unwrap();
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V2>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.replace("kid", "mid").as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V2>::try_from(VALID_LOCAL_TOKEN).unwrap(),
                Some(FOOTER.replace("kid", "mid").as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_footer_in_token_none_supplied() {
        let test_pk = AsymmetricPublicKey::<V2>::from(&TEST_PK_BYTES).unwrap();
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V2>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(b"")
            )
            .unwrap_err(),
            Error::TokenValidation
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V2>::try_from(VALID_LOCAL_TOKEN).unwrap(),
                Some(b"")
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_no_footer_in_token_some_supplied() {
        let test_pk = AsymmetricPublicKey::<V2>::from(&TEST_PK_BYTES).unwrap();
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        let split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        let invalid_public: String = format!(
            "{}.{}.{}",
            split_public[0], split_public[1], split_public[2]
        );

        let split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let invalid_local: String =
            format!("{}.{}.{}", split_local[0], split_local[1], split_local[2]);

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V2>::try_from(&invalid_public).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V2>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_signature() {
        let test_pk = AsymmetricPublicKey::<V2>::from(&TEST_PK_BYTES).unwrap();

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
                &UntrustedToken::<Public, V2>::try_from(&invalid_public).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_tag() {
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_tag = decode_b64(split_local[2]).unwrap();
        let tlen = bad_tag.len();
        bad_tag.copy_within(0..16, tlen - 16);
        let tmp = encode_b64(bad_tag).unwrap();
        split_local[2] = &tmp;
        let invalid_local: String = format!(
            "{}.{}.{}.{}",
            split_local[0], split_local[1], split_local[2], split_local[3]
        );

        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V2>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_ciphertext() {
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_ct = decode_b64(split_local[2]).unwrap();
        let ctlen = bad_ct.len();
        bad_ct.copy_within((ctlen - 16)..ctlen, 24);
        let tmp = encode_b64(bad_ct).unwrap();
        split_local[2] = &tmp;
        let invalid_local: String = format!(
            "{}.{}.{}.{}",
            split_local[0], split_local[1], split_local[2], split_local[3]
        );

        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V2>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_nonce() {
        let test_local_sk = SymmetricKey::<V2>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_nonce = decode_b64(split_local[2]).unwrap();
        let nlen = bad_nonce.len();
        bad_nonce.copy_within((nlen - 24)..nlen, 0);
        let tmp = encode_b64(bad_nonce).unwrap();
        split_local[2] = &tmp;
        let invalid_local: String = format!(
            "{}.{}.{}.{}",
            split_local[0], split_local[1], split_local[2], split_local[3]
        );

        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V2>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_invalid_public_secret_key() {
        let bad_pk = AsymmetricPublicKey::<V2>::from(&[0u8; 32]).unwrap();

        assert_eq!(
            PublicToken::verify(
                &bad_pk,
                &UntrustedToken::<Public, V2>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_invalid_shared_secret_key() {
        let bad_local_sk = SymmetricKey::<V2>::from(&[0u8; 32]).unwrap();

        assert_eq!(
            LocalToken::decrypt(
                &bad_local_sk,
                &UntrustedToken::<Local, V2>::try_from(VALID_LOCAL_TOKEN).unwrap(),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }
}

#[cfg(test)]
mod test_keys {
    use super::*;
    use crate::version2::test_tokens::TEST_SK_BYTES;

    #[test]
    fn test_symmetric_gen() {
        let randomv = SymmetricKey::<V2>::generate().unwrap();
        assert_ne!(randomv.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_invalid_sizes() {
        assert!(AsymmetricSecretKey::<V2>::from(&[1u8; 63]).is_err());
        assert!(AsymmetricSecretKey::<V2>::from(&TEST_SK_BYTES).is_ok());
        assert!(AsymmetricSecretKey::<V2>::from(&[1u8; 65]).is_err());

        assert!(AsymmetricPublicKey::<V2>::from(&[1u8; 31]).is_err());
        assert!(AsymmetricPublicKey::<V2>::from(&[1u8; 32]).is_ok());
        assert!(AsymmetricPublicKey::<V2>::from(&[1u8; 33]).is_err());

        assert!(SymmetricKey::<V2>::from(&[0u8; 31]).is_err());
        assert!(SymmetricKey::<V2>::from(&[0u8; 32]).is_ok());
        assert!(SymmetricKey::<V2>::from(&[0u8; 33]).is_err());
    }

    #[test]
    fn try_from_secret_to_public() {
        let kpv2 = AsymmetricKeyPair::<V2>::generate().unwrap();
        let pubv2 = AsymmetricPublicKey::<V2>::try_from(&kpv2.secret).unwrap();
        assert_eq!(pubv2.as_bytes(), kpv2.public.as_bytes());
        assert_eq!(pubv2, kpv2.public);
        assert_eq!(&kpv2.secret.as_bytes()[32..], pubv2.as_bytes());
    }

    #[test]
    fn test_trait_impls() {
        let debug = format!("{:?}", SymmetricKey::<V2>::generate().unwrap());
        assert_eq!(debug, "SymmetricKey {***OMITTED***}");

        let randomv = SymmetricKey::<V2>::generate().unwrap();
        let zero = SymmetricKey::<V2>::from(&[0u8; V2::LOCAL_KEY]).unwrap();
        assert_ne!(randomv, zero);

        let debug = format!("{:?}", AsymmetricKeyPair::<V2>::generate().unwrap().secret);
        assert_eq!(debug, "AsymmetricSecretKey {***OMITTED***}");

        let random1 = AsymmetricKeyPair::<V2>::generate().unwrap();
        let random2 = AsymmetricKeyPair::<V2>::generate().unwrap();
        assert_ne!(random1.secret, random2.secret);
    }

    #[test]
    fn test_clone() {
        let sk = SymmetricKey::<V2>::generate().unwrap();
        assert_eq!(sk, sk.clone());

        let kp = AsymmetricKeyPair::<V2>::generate().unwrap();
        assert_eq!(kp.secret, kp.secret.clone());
        assert_eq!(kp.public, kp.public.clone());
    }
}
