use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;

use crate::errors::Errors;
use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey, Version};

use orion::hazardous::hash::blake2b;
use orion::hazardous::hash::blake2b::Blake2b;

use crate::common::{decode_b64, encode_b64, validate_format_footer};
use crate::pae;
use orion::hazardous::stream::xchacha20;

use blake2b::SecretKey as AuthKey;
use xchacha20::Nonce as EncNonce;
use xchacha20::SecretKey as EncKey;

/// PASETO v4 public tokens.
pub struct PublicToken;

impl PublicToken {
    /// The header and purpose for the public token: `v4.public.`.
    pub const HEADER: &'static str = "v4.public.";

    /// Create a public token.
    pub fn sign(
        secret_key: &AsymmetricSecretKey,
        public_key: &AsymmetricPublicKey,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Errors> {
        use ed25519_dalek::Keypair;
        use ed25519_dalek::PublicKey;
        use ed25519_dalek::SecretKey;
        use ed25519_dalek::Signer;

        if secret_key.version != Version::V4 || public_key.version != Version::V4 {
            return Err(Errors::KeyError);
        }
        if message.is_empty() {
            return Err(Errors::EmptyPayloadError);
        }

        let secret = SecretKey::from_bytes(secret_key.as_bytes());
        let public = PublicKey::from_bytes(public_key.as_bytes());

        let kp: Keypair = match (secret, public) {
            (Ok(sk), Ok(pk)) => Keypair {
                secret: sk,
                public: pk,
            },
            _ => return Err(Errors::KeyError),
        };

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);
        let m2 = pae::pae(&[Self::HEADER.as_bytes(), message, f, i])?;
        let sig = kp.sign(m2.as_ref());

        let mut m_sig: Vec<u8> = Vec::from(message);
        m_sig.extend_from_slice(sig.to_bytes().as_ref());

        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(m_sig)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Verify a public token.
    pub fn verify(
        public_key: &AsymmetricPublicKey,
        token: &str,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<(), Errors> {
        use ed25519_dalek::PublicKey;
        use ed25519_dalek::Signature;

        if public_key.version != Version::V4 {
            return Err(Errors::KeyError);
        }
        if token.is_empty() {
            return Err(Errors::EmptyPayloadError);
        }

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);

        let parts_split = validate_format_footer(Self::HEADER, token, f)?;
        let sm = decode_b64(parts_split[2])?;
        if sm.len() < ed25519_dalek::SIGNATURE_LENGTH {
            return Err(Errors::TokenFormatError);
        }

        let m = sm[..(sm.len() - ed25519_dalek::SIGNATURE_LENGTH)].as_ref();
        let s = sm[m.len()..m.len() + ed25519_dalek::SIGNATURE_LENGTH].as_ref();

        let m2 = pae::pae(&[Self::HEADER.as_bytes(), m, f, i])?;
        let pk: PublicKey = match PublicKey::from_bytes(public_key.as_bytes()) {
            Ok(val) => val,
            Err(_) => return Err(Errors::KeyError),
        };

        debug_assert!(s.len() == ed25519_dalek::SIGNATURE_LENGTH);
        // If the below fails, it is an invalid signature.
        let sig = match Signature::try_from(s) {
            Ok(val) => val,
            Err(_) => return Err(Errors::TokenValidationError),
        };

        if pk.verify_strict(m2.as_ref(), &sig).is_ok() {
            Ok(())
        } else {
            Err(Errors::TokenValidationError)
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

    /// The length of the random nonce used for BLAKE2b.
    const N_LEN: usize = 32;

    const M1_LEN: usize = Self::N_LEN + Self::DOMAIN_SEPARATOR_ENC.as_bytes().len();
    const M2_LEN: usize = Self::N_LEN + Self::DOMAIN_SEPARATOR_AUTH.as_bytes().len();

    /// Length of the BLAKE2b tag.
    const TAG_LEN: usize = 32;

    /// Split the user-provided secret key into keys used for encryption and authentication.
    fn key_split(sk: &[u8], n: &[u8]) -> Result<(EncKey, EncNonce, AuthKey), Errors> {
        debug_assert_eq!(n.len(), 32);
        debug_assert_eq!(sk.len(), 32);

        let mut m1 = [0u8; Self::M1_LEN];
        m1[..21].copy_from_slice(Self::DOMAIN_SEPARATOR_ENC.as_bytes());
        m1[21..].copy_from_slice(n);

        let mut m2 = [0u8; Self::M2_LEN];
        m2[..24].copy_from_slice(Self::DOMAIN_SEPARATOR_AUTH.as_bytes());
        m2[24..].copy_from_slice(n);

        let sk = blake2b::SecretKey::from_slice(sk).unwrap();
        let mut b2_ctx = Blake2b::new(Some(&sk), 56).unwrap();
        b2_ctx.update(&m1).unwrap();
        let tmp = b2_ctx.finalize().unwrap();
        let enc_key = EncKey::from_slice(&tmp.as_ref()[..32]).unwrap();
        let n2 = EncNonce::from_slice(&tmp.as_ref()[32..]).unwrap();

        b2_ctx = Blake2b::new(Some(&sk), 32).unwrap();
        b2_ctx.update(&m2).unwrap();
        let auth_key = AuthKey::from_slice(b2_ctx.finalize().unwrap().as_ref()).unwrap();

        Ok((enc_key, n2, auth_key))
    }

    /// Encrypt and authenticate a message using nonce directly.
    pub(crate) fn encrypt_with_nonce(
        secret_key: &SymmetricKey,
        nonce: &[u8],
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Errors> {
        debug_assert_eq!(nonce.len(), 32);

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);

        let (enc_key, n2, auth_key) = Self::key_split(secret_key.as_bytes(), nonce)?;

        let mut ciphertext = vec![0u8; message.len()];
        xchacha20::encrypt(&enc_key, &n2, 0, message, &mut ciphertext)
            .map_err(|_| Errors::EncryptError)?;
        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), nonce, ciphertext.as_slice(), f, i])?;

        let mut b2_ctx = Blake2b::new(Some(&auth_key), Self::TAG_LEN).unwrap();
        b2_ctx
            .update(pre_auth.as_slice())
            .map_err(|_| Errors::EncryptError)?;
        let tag = b2_ctx.finalize().map_err(|_| Errors::EncryptError)?;

        // nonce and tag lengths are both 32, so obviously safe to op::add
        let concat_len: usize = match (nonce.len() + tag.len()).checked_add(ciphertext.len()) {
            Some(len) => len,
            None => return Err(Errors::EncryptError),
        };
        let mut concat = vec![0u8; concat_len];
        concat[..32].copy_from_slice(nonce);
        concat[32..32 + ciphertext.len()].copy_from_slice(ciphertext.as_slice());
        concat[concat_len - Self::TAG_LEN..].copy_from_slice(tag.as_ref());

        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(concat)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Create a local token.
    pub fn encrypt(
        secret_key: &SymmetricKey,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Errors> {
        if secret_key.version != Version::V4 {
            return Err(Errors::KeyError);
        }
        if message.is_empty() {
            return Err(Errors::EmptyPayloadError);
        }

        let mut n = [0u8; 32];
        getrandom::getrandom(&mut n)?;

        Self::encrypt_with_nonce(secret_key, &n, message, footer, implicit_assert)
    }

    #[allow(clippy::many_single_char_names)] // The single-char names match those in the spec
    /// Verify and decrypt a local token.
    pub fn decrypt(
        secret_key: &SymmetricKey,
        token: &str,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<Vec<u8>, Errors> {
        if secret_key.version != Version::V4 {
            return Err(Errors::KeyError);
        }
        if token.is_empty() {
            return Err(Errors::EmptyPayloadError);
        }

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);
        let parts_split = validate_format_footer(Self::HEADER, token, f)?;

        let nc = decode_b64(parts_split[2])?;
        if nc.len() < (Self::N_LEN + Self::TAG_LEN) {
            return Err(Errors::TokenFormatError);
        }
        let mut n: [u8; 32] = [0u8; 32];
        n.copy_from_slice(nc[..32].as_ref());
        let c = nc[n.len()..nc.len() - 32].as_ref();
        if c.is_empty() {
            return Err(Errors::EmptyPayloadError);
        }
        let t = nc[nc.len() - Self::TAG_LEN..].as_ref();

        let (enc_key, n2, auth_key) = Self::key_split(secret_key.as_bytes(), &n)?;

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), n.as_ref(), c, f, i])?;
        let expected_tag =
            blake2b::Digest::from_slice(t).map_err(|_| Errors::TokenValidationError)?;
        blake2b::Blake2b::verify(&expected_tag, &auth_key, 32, pre_auth.as_slice())
            .map_err(|_| Errors::TokenValidationError)?;

        let mut out = vec![0u8; c.len()];
        xchacha20::decrypt(&enc_key, &n2, 0, c, &mut out)
            .map_err(|_| Errors::TokenValidationError)?;
        Ok(out)
    }
}

#[cfg(test)]
mod test_vectors {

    use hex;

    use super::*;
    use std::fs::File;
    use std::io::BufReader;

    use crate::claims::Claims;
    use crate::common::tests::*;
    use crate::keys::Version;

    fn test_local(test: &PasetoTest) {
        debug_assert!(test.nonce.is_some());
        debug_assert!(test.key.is_some());

        let sk = SymmetricKey::from(
            &hex::decode(test.key.as_ref().unwrap()).unwrap(),
            Version::V4,
        )
        .unwrap();

        let nonce = hex::decode(test.nonce.as_ref().unwrap()).unwrap();
        let footer = test.footer.as_bytes();
        let implicit_assert = test.implicit_assertion.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            assert!(
                LocalToken::decrypt(&sk, &test.token, Some(footer), Some(implicit_assert)).is_err()
            );

            return;
        }

        let message = serde_json::to_string(test.payload.as_ref().unwrap()).unwrap();

        let actual = LocalToken::encrypt_with_nonce(
            &sk,
            &nonce,
            message.as_bytes(),
            Some(footer),
            Some(implicit_assert),
        )
        .unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);

        let roundtrip =
            LocalToken::decrypt(&sk, &test.token, Some(footer), Some(implicit_assert)).unwrap();
        assert_eq!(roundtrip, message.as_bytes(), "Failed {:?}", test.name);

        let parsed_claims = Claims::from_bytes(&roundtrip).unwrap();
        assert_eq!(
            parsed_claims.get_claim("data").unwrap().as_str().unwrap(),
            test.payload.as_ref().unwrap().data
        );
        assert_eq!(
            parsed_claims.get_claim("exp").unwrap().as_str().unwrap(),
            test.payload.as_ref().unwrap().exp
        );
    }

    fn test_public(test: &PasetoTest) {
        debug_assert!(test.public_key.is_some());
        debug_assert!(test.secret_key.is_some());

        let sk = AsymmetricSecretKey::from(
            &hex::decode(test.secret_key.as_ref().unwrap()).unwrap()[..32],
            Version::V4,
        )
        .unwrap();
        let pk = AsymmetricPublicKey::from(
            &hex::decode(test.public_key.as_ref().unwrap()).unwrap(),
            Version::V4,
        )
        .unwrap();
        let footer = test.footer.as_bytes();
        let implicit_assert = test.implicit_assertion.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            assert!(
                PublicToken::verify(&pk, &test.token, Some(footer), Some(implicit_assert)).is_err()
            );

            return;
        }

        let message = serde_json::to_string(test.payload.as_ref().unwrap()).unwrap();

        let actual = PublicToken::sign(
            &sk,
            &pk,
            message.as_bytes(),
            Some(footer),
            Some(implicit_assert),
        )
        .unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);
        assert!(
            PublicToken::verify(&pk, &test.token, Some(footer), Some(implicit_assert)).is_ok(),
            "Failed {:?}",
            test.name
        );
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
mod tests {
    use super::*;
    use crate::keys::{SymmetricKey, Version};

    // In version 2 tests, the SK used for public tokens is valid for the local as well.
    // Not the case with version 4.
    const TEST_LOCAL_SK_BYTES: [u8; 32] = [
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
        130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    ];

    const TEST_SK_BYTES: [u8; 32] = [
        180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125,
        159, 133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116,
    ];

    const TEST_PK_BYTES: [u8; 32] = [
        30, 185, 219, 187, 188, 4, 124, 3, 253, 112, 96, 78, 0, 113, 240, 152, 126, 22, 178, 139,
        117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177, 162,
    ];

    const MESSAGE: &'static str =
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const FOOTER: &'static str = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const VALID_PUBLIC_TOKEN: &'static str = "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const VALID_LOCAL_TOKEN: &'static str = "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    #[test]
    fn test_roundtrip_local() {
        let sk = SymmetricKey::gen(Version::V4).unwrap();
        let message = b"token payload";

        let token = LocalToken::encrypt(&sk, message, None, None).unwrap();
        let payload = LocalToken::decrypt(&sk, &token, None, None).unwrap();

        assert_eq!(payload, message);
    }

    #[test]
    fn test_roundtrip_public() {
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();

        let token = PublicToken::sign(&test_sk, &test_pk, MESSAGE.as_bytes(), None, None).unwrap();
        assert!(PublicToken::verify(&test_pk, &token, None, None).is_ok());
    }

    #[test]
    fn footer_none_some_empty_is_same() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
        let footer = b"";

        let actual_some =
            PublicToken::sign(&test_sk, &test_pk, message, Some(footer), None).unwrap();
        let actual_none = PublicToken::sign(&test_sk, &test_pk, message, None, None).unwrap();
        assert_eq!(actual_some, actual_none);

        assert!(PublicToken::verify(&test_pk, &actual_none, Some(footer), None).is_ok());
        assert!(PublicToken::verify(&test_pk, &actual_some, None, None).is_ok());

        let actual_some = LocalToken::encrypt(&test_local_sk, message, Some(footer), None).unwrap();
        let actual_none = LocalToken::encrypt(&test_local_sk, message, None, None).unwrap();
        // They don't equal because the nonce is random. So we only check decryption.

        assert!(LocalToken::decrypt(&test_local_sk, &actual_none, Some(footer), None).is_ok());
        assert!(LocalToken::decrypt(&test_local_sk, &actual_some, None, None).is_ok());
    }

    #[test]
    fn implicit_none_some_empty_is_same() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
        let implicit = b"";

        let actual_some =
            PublicToken::sign(&test_sk, &test_pk, message, None, Some(implicit)).unwrap();
        let actual_none = PublicToken::sign(&test_sk, &test_pk, message, None, None).unwrap();
        assert_eq!(actual_some, actual_none);

        assert!(PublicToken::verify(&test_pk, &actual_none, None, Some(implicit)).is_ok());
        assert!(PublicToken::verify(&test_pk, &actual_some, None, None).is_ok());

        let actual_some =
            LocalToken::encrypt(&test_local_sk, message, None, Some(implicit)).unwrap();
        let actual_none = LocalToken::encrypt(&test_local_sk, message, None, None).unwrap();
        // They don't equal because the nonce is random. So we only check decryption.

        assert!(LocalToken::decrypt(&test_local_sk, &actual_none, None, Some(implicit)).is_ok());
        assert!(LocalToken::decrypt(&test_local_sk, &actual_some, None, None).is_ok());
    }

    #[test]
    fn fuzztest_bug_one() {
        let sk1 = SymmetricKey::from(
            &[
                141, 225, 124, 245, 68, 230, 197, 175, 179, 197, 127, 83, 207, 183, 85, 164, 230,
                24, 14, 91, 230, 213, 164, 30, 243, 64, 184, 132, 198, 120, 44, 228,
            ],
            Version::V4,
        )
        .unwrap();

        let crashing_token =
            "v4.local.444444bbbbb444444444bbb444444bbb44444444444444888888888888888cJJbbb44444444";
        assert!(LocalToken::decrypt(&sk1, &crashing_token, None, None).is_err());
    }

    #[test]
    // NOTE: See https://github.com/paseto-standard/paseto-spec/issues/17
    fn empty_payload() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();

        assert_eq!(
            PublicToken::sign(&test_sk, &test_pk, b"", None, None).unwrap_err(),
            Errors::EmptyPayloadError
        );
        assert_eq!(
            PublicToken::verify(&test_pk, "", None, None).unwrap_err(),
            Errors::EmptyPayloadError
        );
        assert_eq!(
            LocalToken::encrypt(&test_local_sk, b"", None, None).unwrap_err(),
            Errors::EmptyPayloadError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, "", None, None).unwrap_err(),
            Errors::EmptyPayloadError
        );
    }

    #[test]
    // NOTE: "Algorithm lucidity" from spec.
    fn wrong_key_version() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        assert_eq!(
            PublicToken::sign(&test_sk, &test_pk, b"test", None, None).unwrap_err(),
            Errors::KeyError
        );
        assert_eq!(
            PublicToken::verify(&test_pk, "test", None, None).unwrap_err(),
            Errors::KeyError
        );
        assert_eq!(
            LocalToken::encrypt(&test_local_sk, b"test", None, None).unwrap_err(),
            Errors::KeyError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, "test", None, None).unwrap_err(),
            Errors::KeyError
        );
    }

    #[test]
    fn err_on_modified_header() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("v4", "v2"),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("v4", "v2"),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("v4", ""),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("v4", ""),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    fn err_on_modified_purpose() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("public", "local"),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("local", "public"),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("public", ""),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("local", ""),
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    // NOTE: Missing but created with one
    fn err_on_missing_payload() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        split_public[2] = "";
        let invalid_public: String = split_public.iter().map(|x| *x).collect();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        split_local[2] = "";
        let invalid_local: String = split_local.iter().map(|x| *x).collect();

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &invalid_local,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    fn err_on_extra_after_footer() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        split_public.push(".shouldNotBeHere");
        let invalid_public: String = split_public.iter().map(|x| *x).collect();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        split_local.push(".shouldNotBeHere");
        let invalid_local: String = split_local.iter().map(|x| *x).collect();

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &invalid_local,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    fn err_on_modified_footer() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN,
                Some(&FOOTER.replace("kid", "mid").as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN,
                Some(&FOOTER.replace("kid", "mid").as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_wrong_implicit_assert() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();
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
            Errors::TokenValidationError
        );
        assert!(LocalToken::decrypt(
            &test_local_sk,
            &VALID_LOCAL_TOKEN,
            Some(FOOTER.as_bytes()),
            None
        )
        .is_ok());
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN,
                Some(FOOTER.as_bytes()),
                Some(b"WRONG IMPLICIT")
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_footer_in_token_none_supplied() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        assert_eq!(
            PublicToken::verify(&test_pk, &VALID_PUBLIC_TOKEN, Some(b""), None).unwrap_err(),
            Errors::TokenValidationError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, &VALID_LOCAL_TOKEN, Some(b""), None).unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_no_footer_in_token_some_supplied() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        let split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        let invalid_public: String = format!(
            "{}.{}.{}",
            split_public[0], split_public[1], split_public[2]
        );

        let split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let invalid_local: String =
            format!("{}.{}.{}", split_local[0], split_local[1], split_local[2]);

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Errors::TokenValidationError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &invalid_local,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_signature() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();

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
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_tag() {
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_tag = Vec::from(decode_b64(split_local[2]).unwrap());
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
                &invalid_local,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_ciphertext() {
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_ct = Vec::from(decode_b64(split_local[2]).unwrap());
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
                &invalid_local,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_nonce() {
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_nonce = Vec::from(decode_b64(split_local[2]).unwrap());
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
                &invalid_local,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_invalid_base64() {
        let test_local_sk = SymmetricKey::from(&TEST_LOCAL_SK_BYTES, Version::V4).unwrap();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let mut bad_nonce = Vec::from(decode_b64(split_local[2]).unwrap());
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
                &invalid_local,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_invalid_public_secret_key() {
        let bad_pk = AsymmetricPublicKey::from(&[0u8; 32], Version::V4).unwrap();

        assert_eq!(
            PublicToken::verify(&bad_pk, VALID_PUBLIC_TOKEN, Some(FOOTER.as_bytes()), None)
                .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_invalid_shared_secret_key() {
        let bad_local_sk = SymmetricKey::from(&[0u8; 32], Version::V4).unwrap();

        assert_eq!(
            LocalToken::decrypt(
                &bad_local_sk,
                VALID_LOCAL_TOKEN,
                Some(FOOTER.as_bytes()),
                None
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }
}
