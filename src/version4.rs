#![cfg_attr(docsrs, doc(cfg(feature = "v4")))]

use core::convert::TryFrom;
use core::marker::PhantomData;

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
use blake2b::SecretKey as AuthKey;
use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed, Signature};
use orion::hazardous::mac::blake2b;
use orion::hazardous::mac::blake2b::Blake2b;
use orion::hazardous::stream::xchacha20;
use subtle::ConstantTimeEq;
use xchacha20::Nonce as EncNonce;
use xchacha20::SecretKey as EncKey;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Version 4 of the PASETO spec.
pub struct V4;

impl Version for V4 {
    const LOCAL_KEY: usize = 32;
    const SECRET_KEY: usize = 32 + Self::PUBLIC_KEY; // Seed || PK
    const PUBLIC_KEY: usize = 32;
    const PUBLIC_SIG: usize = 64;
    const LOCAL_NONCE: usize = 32;
    const LOCAL_TAG: usize = 32;
    const PUBLIC_HEADER: &'static str = "v4.public.";
    const LOCAL_HEADER: &'static str = "v4.local.";
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

impl TryFrom<&AsymmetricSecretKey<V4>> for AsymmetricPublicKey<V4> {
    type Error = Error;

    fn try_from(value: &AsymmetricSecretKey<V4>) -> Result<Self, Self::Error> {
        AsymmetricPublicKey::<V4>::from(&value.as_bytes()[32..])
    }
}

impl Generate<AsymmetricKeyPair<V4>, V4> for AsymmetricKeyPair<V4> {
    fn generate() -> Result<AsymmetricKeyPair<V4>, Error> {
        let key_pair = KeyPair::generate();

        let secret = AsymmetricSecretKey::<V4>::from(key_pair.sk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;
        let public = AsymmetricPublicKey::<V4>::from(key_pair.pk.as_ref())
            .map_err(|_| Error::KeyGeneration)?;

        Ok(Self { public, secret })
    }
}

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

/// PASETO v4 public tokens.
pub struct PublicToken;

impl PublicToken {
    /// The header and purpose for the public token: `v4.public.`.
    pub const HEADER: &'static str = "v4.public.";

    /// Create a public token.
    pub fn sign(
        secret_key: &AsymmetricSecretKey<V4>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let sk = SecretKey::from_slice(secret_key.as_bytes()).map_err(|_| Error::Key)?;

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);
        let m2 = pae::pae(&[Self::HEADER.as_bytes(), message, f, i])?;
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
        public_key: &AsymmetricPublicKey<V4>,
        token: &UntrustedToken<Public, V4>,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let i = implicit_assert.unwrap_or(&[]);
        let sm = token.untrusted_message();
        let m = token.untrusted_payload();
        let s = sm[m.len()..m.len() + V4::PUBLIC_SIG].as_ref();

        let m2 = pae::pae(&[Self::HEADER.as_bytes(), m, f, i])?;
        let pk: PublicKey = PublicKey::from_slice(public_key.as_bytes()).map_err(|_| Error::Key)?;

        debug_assert!(s.len() == V4::PUBLIC_SIG);
        // If the below fails, it is an invalid signature.
        let sig = Signature::from_slice(s).map_err(|_| Error::TokenValidation)?;

        if pk.verify(m2, &sig).is_ok() {
            TrustedToken::_new(Self::HEADER, m, f, i)
        } else {
            Err(Error::TokenValidation)
        }
    }
}

/// PASETO v4 local tokens.
pub struct LocalToken;

impl LocalToken {
    /// The header and purpose for the local token: `v4.local.`.
    pub const HEADER: &'static str = "v4.local.";

    /// Domain separator for key-splitting the encryption key (21 in length as bytes).
    const DOMAIN_SEPARATOR_ENC: &'static str = "paseto-encryption-key";

    /// Domain separator for key-splitting the authentication key (24 in length as bytes).
    const DOMAIN_SEPARATOR_AUTH: &'static str = "paseto-auth-key-for-aead";

    const M1_LEN: usize = V4::LOCAL_NONCE + Self::DOMAIN_SEPARATOR_ENC.as_bytes().len();
    const M2_LEN: usize = V4::LOCAL_NONCE + Self::DOMAIN_SEPARATOR_AUTH.as_bytes().len();

    /// Split the user-provided secret key into keys used for encryption and authentication.
    fn key_split(sk: &[u8], n: &[u8]) -> Result<(EncKey, EncNonce, AuthKey), Error> {
        debug_assert_eq!(n.len(), V4::LOCAL_NONCE);
        debug_assert_eq!(sk.len(), V4::LOCAL_KEY);

        let mut m1 = [0u8; Self::M1_LEN];
        m1[..21].copy_from_slice(Self::DOMAIN_SEPARATOR_ENC.as_bytes());
        m1[21..].copy_from_slice(n);

        let mut m2 = [0u8; Self::M2_LEN];
        m2[..24].copy_from_slice(Self::DOMAIN_SEPARATOR_AUTH.as_bytes());
        m2[24..].copy_from_slice(n);

        let sk = blake2b::SecretKey::from_slice(sk).unwrap();
        let mut b2_ctx = Blake2b::new(&sk, 56).unwrap();
        b2_ctx.update(&m1).unwrap();
        let tmp = b2_ctx.finalize().unwrap();
        let enc_key = EncKey::from_slice(&tmp.unprotected_as_bytes()[..32]).unwrap();
        let n2 = EncNonce::from_slice(&tmp.unprotected_as_bytes()[32..]).unwrap();

        b2_ctx = Blake2b::new(&sk, V4::LOCAL_TAG).unwrap();
        b2_ctx.update(&m2).unwrap();
        let auth_key =
            AuthKey::from_slice(b2_ctx.finalize().unwrap().unprotected_as_bytes()).unwrap();

        Ok((enc_key, n2, auth_key))
    }

    /// Encrypt and authenticate a message using nonce directly.
    pub(crate) fn encrypt_with_nonce(
        secret_key: &SymmetricKey<V4>,
        nonce: &[u8],
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        debug_assert_eq!(nonce.len(), V4::LOCAL_NONCE);
        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);

        let (enc_key, n2, auth_key) = Self::key_split(secret_key.as_bytes(), nonce)?;

        let mut ciphertext = vec![0u8; message.len()];
        xchacha20::encrypt(&enc_key, &n2, 0, message, &mut ciphertext)
            .map_err(|_| Error::Encryption)?;
        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), nonce, ciphertext.as_slice(), f, i])?;

        let mut b2_ctx = Blake2b::new(&auth_key, V4::LOCAL_TAG).unwrap();
        b2_ctx
            .update(pre_auth.as_slice())
            .map_err(|_| Error::Encryption)?;
        let tag = b2_ctx.finalize().map_err(|_| Error::Encryption)?;

        // nonce and tag lengths are both 32, so obviously safe to op::add
        let concat_len: usize = match (nonce.len() + tag.len()).checked_add(ciphertext.len()) {
            Some(len) => len,
            None => return Err(Error::Encryption),
        };
        let mut concat = vec![0u8; concat_len];
        concat[..32].copy_from_slice(nonce);
        concat[32..32 + ciphertext.len()].copy_from_slice(ciphertext.as_slice());
        concat[concat_len - V4::LOCAL_TAG..].copy_from_slice(tag.unprotected_as_bytes());

        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(concat)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Create a local token.
    pub fn encrypt(
        secret_key: &SymmetricKey<V4>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let mut n = [0u8; V4::LOCAL_NONCE];
        getrandom::getrandom(&mut n)?;

        Self::encrypt_with_nonce(secret_key, &n, message, footer, implicit_assert)
    }

    #[allow(clippy::many_single_char_names)] // The single-char names match those in the spec
    /// Verify and decrypt a local token.
    ///
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn decrypt(
        secret_key: &SymmetricKey<V4>,
        token: &UntrustedToken<Local, V4>,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let i = implicit_assert.unwrap_or(&[]);
        let nc = token.untrusted_message();

        let mut n: [u8; 32] = [0u8; V4::LOCAL_NONCE];
        n.copy_from_slice(nc[..V4::LOCAL_NONCE].as_ref());
        let c = token.untrusted_payload();
        let t = nc[nc.len() - V4::LOCAL_TAG..].as_ref();

        let (enc_key, n2, auth_key) = Self::key_split(secret_key.as_bytes(), &n)?;

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), n.as_ref(), c, f, i])?;
        let expected_tag = blake2b::Tag::from_slice(t).map_err(|_| Error::TokenValidation)?;
        Blake2b::verify(&expected_tag, &auth_key, 32, pre_auth.as_slice())
            .map_err(|_| Error::TokenValidation)?;

        let mut out = vec![0u8; c.len()];
        xchacha20::decrypt(&enc_key, &n2, 0, c, &mut out).map_err(|_| Error::TokenValidation)?;

        TrustedToken::_new(Self::HEADER, &out, f, i)
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
            SymmetricKey::<V4>::from(&hex::decode(test.key.as_ref().unwrap()).unwrap()).unwrap();

        let nonce = hex::decode(test.nonce.as_ref().unwrap()).unwrap();
        let footer: Option<&[u8]> = if test.footer.as_bytes().is_empty() {
            None
        } else {
            Some(test.footer.as_bytes())
        };
        let implicit_assert = test.implicit_assertion.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            if let Ok(ut) = UntrustedToken::<Local, V4>::try_from(&test.token) {
                assert!(LocalToken::decrypt(&sk, &ut, footer, Some(implicit_assert)).is_err());
            }

            return;
        }

        let message = test.payload.as_ref().unwrap().as_str().unwrap();

        let actual = LocalToken::encrypt_with_nonce(
            &sk,
            &nonce,
            message.as_bytes(),
            footer,
            Some(implicit_assert),
        )
        .unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);

        let ut = UntrustedToken::<Local, V4>::try_from(&test.token).unwrap();
        let trusted = LocalToken::decrypt(&sk, &ut, footer, Some(implicit_assert)).unwrap();
        assert_eq!(trusted.payload(), message, "Failed {:?}", test.name);
        assert_eq!(trusted.footer(), test.footer.as_bytes());
        assert_eq!(trusted.header(), LocalToken::HEADER);
        assert_eq!(trusted.implicit_assert(), implicit_assert);

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

        let sk = AsymmetricSecretKey::<V4>::from(
            &hex::decode(test.secret_key.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        let pk = AsymmetricPublicKey::<V4>::from(
            &hex::decode(test.public_key.as_ref().unwrap()).unwrap(),
        )
        .unwrap();
        let footer: Option<&[u8]> = if test.footer.as_bytes().is_empty() {
            None
        } else {
            Some(test.footer.as_bytes())
        };
        let implicit_assert = test.implicit_assertion.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            if let Ok(ut) = UntrustedToken::<Public, V4>::try_from(&test.token) {
                assert!(PublicToken::verify(&pk, &ut, footer, Some(implicit_assert)).is_err());
            }

            return;
        }

        let message = test.payload.as_ref().unwrap().as_str().unwrap();

        let actual =
            PublicToken::sign(&sk, message.as_bytes(), footer, Some(implicit_assert)).unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);
        let ut = UntrustedToken::<Public, V4>::try_from(&test.token).unwrap();

        let trusted = PublicToken::verify(&pk, &ut, footer, Some(implicit_assert)).unwrap();
        assert_eq!(trusted.payload(), message);
        assert_eq!(trusted.footer(), test.footer.as_bytes());
        assert_eq!(trusted.header(), PublicToken::HEADER);
        assert_eq!(trusted.implicit_assert(), implicit_assert);
    }

    #[test]
    fn run_test_vectors() {
        let path = "./test_vectors/v4.json";
        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let tests: TestFile = serde_json::from_reader(reader).unwrap();

        for t in tests.tests {
            // v4.public
            if t.public_key.is_some() {
                test_public(&t);
            }
            // v4.local
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
    use crate::keys::{AsymmetricKeyPair, Generate, SymmetricKey};
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
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const FOOTER: &str = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const VALID_PUBLIC_TOKEN: &str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const VALID_LOCAL_TOKEN: &str = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    #[test]
    fn test_gen_keypair() {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();

        let token = PublicToken::sign(&kp.secret, MESSAGE.as_bytes(), None, None).unwrap();

        let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();
        assert!(PublicToken::verify(&kp.public, &ut, None, None).is_ok());
    }

    #[test]
    fn test_untrusted_token_usage() {
        // Local
        let sk = SymmetricKey::<V4>::generate().unwrap();
        let token =
            LocalToken::encrypt(&sk, MESSAGE.as_bytes(), Some(FOOTER.as_bytes()), None).unwrap();

        let untrusted_token = UntrustedToken::<Local, V4>::try_from(token.as_str()).unwrap();
        let _ = LocalToken::decrypt(
            &sk,
            &untrusted_token,
            Some(untrusted_token.untrusted_footer()),
            None,
        )
        .unwrap();

        // Public
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        let token = PublicToken::sign(
            &kp.secret,
            MESSAGE.as_bytes(),
            Some(FOOTER.as_bytes()),
            None,
        )
        .unwrap();

        let untrusted_token = UntrustedToken::<Public, V4>::try_from(token.as_str()).unwrap();
        assert!(
            PublicToken::verify(&kp.public, &untrusted_token, Some(FOOTER.as_bytes()), None)
                .is_ok()
        );
    }

    #[test]
    fn test_roundtrip_local() {
        let sk = SymmetricKey::<V4>::generate().unwrap();
        let message = "token payload";

        let token = LocalToken::encrypt(&sk, message.as_bytes(), None, None).unwrap();
        let ut = UntrustedToken::<Local, V4>::try_from(&token).unwrap();
        let trusted_token = LocalToken::decrypt(&sk, &ut, None, None).unwrap();

        assert_eq!(trusted_token.payload(), message);
    }

    #[test]
    fn test_roundtrip_public() {
        let test_sk = AsymmetricSecretKey::<V4>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();

        let token = PublicToken::sign(&test_sk, MESSAGE.as_bytes(), None, None).unwrap();
        let ut = UntrustedToken::<Public, V4>::try_from(&token).unwrap();

        assert!(PublicToken::verify(&test_pk, &ut, None, None).is_ok());
    }

    #[test]
    fn footer_logic() {
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();
        let test_sk = AsymmetricSecretKey::<V4>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";

        // We create a token with Some(footer) and with None
        let actual_some = UntrustedToken::<Public, V4>::try_from(
            &PublicToken::sign(&test_sk, message, Some(FOOTER.as_bytes()), None).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Public, V4>::try_from(
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

        let actual_some = UntrustedToken::<Local, V4>::try_from(
            &LocalToken::encrypt(&test_local_sk, message, Some(FOOTER.as_bytes()), None).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Local, V4>::try_from(
            &LocalToken::encrypt(&test_local_sk, message, None, None).unwrap(),
        )
        .unwrap();

        // They don't equal because the nonce is random. So we only check decryption.
        assert!(LocalToken::decrypt(&test_local_sk, &actual_some, None, None).is_ok());
        assert!(
            LocalToken::decrypt(&test_local_sk, &actual_some, Some(FOOTER.as_bytes()), None)
                .is_ok()
        );
        assert!(
            LocalToken::decrypt(&test_local_sk, &actual_none, Some(FOOTER.as_bytes()), None)
                .is_err()
        );
    }

    #[test]
    fn implicit_none_some_empty_is_same() {
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();
        let test_sk = AsymmetricSecretKey::<V4>::from(&TEST_SK_BYTES).unwrap();
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
        let implicit = b"";

        let actual_some = UntrustedToken::<Public, V4>::try_from(
            &PublicToken::sign(&test_sk, message, None, Some(implicit)).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Public, V4>::try_from(
            &PublicToken::sign(&test_sk, message, None, None).unwrap(),
        )
        .unwrap();
        assert_eq!(actual_some, actual_none);

        assert!(PublicToken::verify(&test_pk, &actual_none, None, Some(implicit)).is_ok());
        assert!(PublicToken::verify(&test_pk, &actual_some, None, None).is_ok());

        let actual_some = UntrustedToken::<Local, V4>::try_from(
            &LocalToken::encrypt(&test_local_sk, message, None, Some(implicit)).unwrap(),
        )
        .unwrap();
        let actual_none = UntrustedToken::<Local, V4>::try_from(
            &LocalToken::encrypt(&test_local_sk, message, None, None).unwrap(),
        )
        .unwrap();
        // They don't equal because the nonce is random. So we only check decryption.

        assert!(LocalToken::decrypt(&test_local_sk, &actual_none, None, Some(implicit)).is_ok());
        assert!(LocalToken::decrypt(&test_local_sk, &actual_some, None, None).is_ok());
    }

    #[test]
    // NOTE: See https://github.com/paseto-standard/paseto-spec/issues/17
    fn empty_payload() {
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();
        let test_sk = AsymmetricSecretKey::<V4>::from(&TEST_SK_BYTES).unwrap();

        assert_eq!(
            PublicToken::sign(&test_sk, b"", None, None).unwrap_err(),
            Error::EmptyPayload
        );
        assert_eq!(
            LocalToken::encrypt(&test_local_sk, b"", None, None).unwrap_err(),
            Error::EmptyPayload
        );
    }

    #[test]
    fn err_on_modified_footer() {
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V4>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.replace("kid", "mid").as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V4>::try_from(VALID_LOCAL_TOKEN).unwrap(),
                Some(FOOTER.replace("kid", "mid").as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_wrong_implicit_assert() {
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();
        assert!(PublicToken::verify(
            &test_pk,
            &UntrustedToken::<Public, V4>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
            Some(FOOTER.as_bytes()),
            None
        )
        .is_ok());
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V4>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.as_bytes()),
                Some(b"WRONG IMPLICIT")
            )
            .unwrap_err(),
            Error::TokenValidation
        );
        assert!(LocalToken::decrypt(
            &test_local_sk,
            &UntrustedToken::<Local, V4>::try_from(VALID_LOCAL_TOKEN).unwrap(),
            Some(FOOTER.as_bytes()),
            None
        )
        .is_ok());
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V4>::try_from(VALID_LOCAL_TOKEN).unwrap(),
                Some(FOOTER.as_bytes()),
                Some(b"WRONG IMPLICIT")
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_footer_in_token_none_supplied() {
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &UntrustedToken::<Public, V4>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(b""),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V4>::try_from(VALID_LOCAL_TOKEN).unwrap(),
                Some(b""),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_no_footer_in_token_some_supplied() {
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();

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
                &UntrustedToken::<Public, V4>::try_from(&invalid_public).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &UntrustedToken::<Local, V4>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_signature() {
        let test_pk = AsymmetricPublicKey::<V4>::from(&TEST_PK_BYTES).unwrap();

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
                &UntrustedToken::<Public, V4>::try_from(&invalid_public).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_tag() {
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();

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
                &UntrustedToken::<Local, V4>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_ciphertext() {
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();

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
                &UntrustedToken::<Local, V4>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_modified_nonce() {
        let test_local_sk = SymmetricKey::<V4>::from(&TEST_LOCAL_SK_BYTES).unwrap();

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
                &UntrustedToken::<Local, V4>::try_from(&invalid_local).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_invalid_public_secret_key() {
        let bad_pk = AsymmetricPublicKey::<V4>::from(&[0u8; 32]).unwrap();

        assert_eq!(
            PublicToken::verify(
                &bad_pk,
                &UntrustedToken::<Public, V4>::try_from(VALID_PUBLIC_TOKEN).unwrap(),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Error::TokenValidation
        );
    }

    #[test]
    fn err_on_invalid_shared_secret_key() {
        let bad_local_sk = SymmetricKey::<V4>::from(&[0u8; 32]).unwrap();

        assert_eq!(
            LocalToken::decrypt(
                &bad_local_sk,
                &UntrustedToken::<Local, V4>::try_from(VALID_LOCAL_TOKEN).unwrap(),
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
    use crate::version4::test_tokens::TEST_SK_BYTES;

    #[test]
    fn test_symmetric_gen() {
        let randomv = SymmetricKey::<V4>::generate().unwrap();
        assert_ne!(randomv.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_invalid_sizes() {
        assert!(AsymmetricSecretKey::<V4>::from(&[1u8; 63]).is_err());
        assert!(AsymmetricSecretKey::<V4>::from(&TEST_SK_BYTES).is_ok());
        assert!(AsymmetricSecretKey::<V4>::from(&[1u8; 65]).is_err());

        assert!(AsymmetricPublicKey::<V4>::from(&[1u8; 31]).is_err());
        assert!(AsymmetricPublicKey::<V4>::from(&[1u8; 32]).is_ok());
        assert!(AsymmetricPublicKey::<V4>::from(&[1u8; 33]).is_err());

        assert!(SymmetricKey::<V4>::from(&[0u8; 31]).is_err());
        assert!(SymmetricKey::<V4>::from(&[0u8; 32]).is_ok());
        assert!(SymmetricKey::<V4>::from(&[0u8; 33]).is_err());
    }

    #[test]
    fn try_from_secret_to_public() {
        let kpv4 = AsymmetricKeyPair::<V4>::generate().unwrap();
        let pubv4 = AsymmetricPublicKey::<V4>::try_from(&kpv4.secret).unwrap();
        assert_eq!(pubv4.as_bytes(), kpv4.public.as_bytes());
        assert_eq!(pubv4, kpv4.public);
        assert_eq!(&kpv4.secret.as_bytes()[32..], pubv4.as_bytes());
    }

    #[test]
    fn test_trait_impls() {
        let debug = format!("{:?}", SymmetricKey::<V4>::generate().unwrap());
        assert_eq!(debug, "SymmetricKey {***OMITTED***}");

        let randomv = SymmetricKey::<V4>::generate().unwrap();
        let zero = SymmetricKey::<V4>::from(&[0u8; V4::LOCAL_KEY]).unwrap();
        assert_ne!(randomv, zero);

        let debug = format!("{:?}", AsymmetricKeyPair::<V4>::generate().unwrap().secret);
        assert_eq!(debug, "AsymmetricSecretKey {***OMITTED***}");

        let random1 = AsymmetricKeyPair::<V4>::generate().unwrap();
        let random2 = AsymmetricKeyPair::<V4>::generate().unwrap();
        assert_ne!(random1.secret, random2.secret);
    }

    #[test]
    fn test_clone() {
        let sk = SymmetricKey::<V4>::generate().unwrap();
        assert_eq!(sk, sk.clone());

        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        assert_eq!(kp.secret, kp.secret.clone());
        assert_eq!(kp.public, kp.public.clone());
    }
}
