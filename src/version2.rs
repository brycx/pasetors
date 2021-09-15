use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;

use crate::common::{decode_b64, encode_b64, validate_format_footer};
use crate::errors::Errors;
use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey, Version};
use crate::pae;

/// PASETO v2 public tokens.
pub struct PublicToken;

impl PublicToken {
    /// The header and purpose for the public token: `v2.public.`.
    pub const HEADER: &'static str = "v2.public.";

    /// Create a public token.
    pub fn sign(
        secret_key: &AsymmetricSecretKey,
        public_key: &AsymmetricPublicKey,
        message: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<String, Errors> {
        use ed25519_dalek::Keypair;
        use ed25519_dalek::PublicKey;
        use ed25519_dalek::SecretKey;
        use ed25519_dalek::Signer;

        if secret_key.version != Version::V2 || public_key.version != Version::V2 {
            return Err(Errors::KeyError);
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
        let m2 = pae::pae(&[Self::HEADER.as_bytes(), message, f])?;
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
    ) -> Result<(), Errors> {
        use ed25519_dalek::PublicKey;
        use ed25519_dalek::Signature;

        if public_key.version != Version::V2 {
            return Err(Errors::KeyError);
        }

        let f = footer.unwrap_or(&[]);

        let parts_split = validate_format_footer(Self::HEADER, token, f)?;
        let sm = decode_b64(parts_split[2])?;
        if sm.len() < ed25519_dalek::SIGNATURE_LENGTH {
            return Err(Errors::TokenFormatError);
        }

        let m = sm[..(sm.len() - ed25519_dalek::SIGNATURE_LENGTH)].as_ref();
        let s = sm[m.len()..m.len() + ed25519_dalek::SIGNATURE_LENGTH].as_ref();

        let m2 = pae::pae(&[Self::HEADER.as_bytes(), m, f])?;
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

/// PASETO v2 local tokens.
pub struct LocalToken;

impl LocalToken {
    /// The header and purpose for the local token: `v2.local.`.
    pub const HEADER: &'static str = "v2.local.";

    /// Encrypt and authenticate a message using nonce_key_bytes to derive a nonce
    /// using BLAKE2b.
    pub(crate) fn encrypt_with_derived_nonce(
        secret_key: &SymmetricKey,
        nonce_key_bytes: &[u8],
        message: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<String, Errors> {
        use orion::hazardous::aead::xchacha20poly1305::*;
        use orion::hazardous::hash::blake2b;
        use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;
        use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;

        debug_assert!(nonce_key_bytes.len() == XCHACHA_NONCESIZE);

        // Safe unwrap()s due to lengths.
        let nonce_key = blake2b::SecretKey::from_slice(nonce_key_bytes).unwrap();
        let mut blake2b = blake2b::Blake2b::new(Some(&nonce_key), XCHACHA_NONCESIZE).unwrap();
        blake2b.update(message.as_ref()).unwrap();
        let nonce = Nonce::from_slice(blake2b.finalize().unwrap().as_ref()).unwrap();

        let f = footer.unwrap_or(&[]);

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), nonce.as_ref(), f])?;
        let mut out = vec![0u8; message.len() + POLY1305_OUTSIZE + nonce.len()];
        let sk = match SecretKey::from_slice(secret_key.as_bytes()) {
            Ok(val) => val,
            Err(orion::errors::UnknownCryptoError) => return Err(Errors::KeyError),
        };

        match seal(
            &sk,
            &nonce,
            message,
            Some(&pre_auth),
            &mut out[nonce.len()..],
        ) {
            Ok(()) => (),
            Err(orion::errors::UnknownCryptoError) => return Err(Errors::EncryptError),
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
        secret_key: &SymmetricKey,
        message: &[u8],
        footer: Option<&[u8]>,
    ) -> Result<String, Errors> {
        use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;

        if secret_key.version != Version::V2 {
            return Err(Errors::KeyError);
        }

        let mut rng_bytes = [0u8; XCHACHA_NONCESIZE];
        getrandom::getrandom(&mut rng_bytes)?;

        Self::encrypt_with_derived_nonce(secret_key, &rng_bytes, message, footer)
    }

    /// Verify and decrypt a local token.
    pub fn decrypt(
        secret_key: &SymmetricKey,
        token: &str,
        footer: Option<&[u8]>,
    ) -> Result<Vec<u8>, Errors> {
        use orion::hazardous::aead::xchacha20poly1305::*;
        use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE;
        use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;

        if secret_key.version != Version::V2 {
            return Err(Errors::KeyError);
        }

        let f = footer.unwrap_or(&[]);
        let parts_split = validate_format_footer(Self::HEADER, token, f)?;
        let nc = decode_b64(parts_split[2])?;
        if nc.len() < (XCHACHA_NONCESIZE + POLY1305_OUTSIZE) {
            return Err(Errors::TokenFormatError);
        }
        let n = nc[..XCHACHA_NONCESIZE].as_ref();
        let c = nc[n.len()..].as_ref();

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), n, f])?;
        let mut out = vec![0u8; c.len() - POLY1305_OUTSIZE];

        let sk = match SecretKey::from_slice(secret_key.as_bytes()) {
            Ok(val) => val,
            Err(orion::errors::UnknownCryptoError) => return Err(Errors::KeyError),
        };

        match open(
            &sk,
            &Nonce::from_slice(n).unwrap(),
            c,
            Some(pre_auth.as_ref()),
            &mut out,
        ) {
            Ok(()) => Ok(out),
            Err(orion::errors::UnknownCryptoError) => Err(Errors::TokenValidationError),
        }
    }
}

#[cfg(test)]
mod test_vectors {

    use hex;

    use super::*;
    use std::fs::File;
    use std::io::BufReader;

    use crate::common::tests::*;
    use crate::keys::Version;

    fn test_local(test: &PasetoTest) {
        debug_assert!(test.nonce.is_some());
        debug_assert!(test.key.is_some());

        let sk = SymmetricKey::from(
            &hex::decode(test.key.as_ref().unwrap()).unwrap(),
            Version::V2,
        )
        .unwrap();

        let nonce = hex::decode(test.nonce.as_ref().unwrap()).unwrap();
        let footer = test.footer.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            assert!(LocalToken::decrypt(&sk, &test.token, Some(footer)).is_err());

            return;
        }

        let message = serde_json::to_string(test.payload.as_ref().unwrap()).unwrap();

        let actual =
            LocalToken::encrypt_with_derived_nonce(&sk, &nonce, message.as_bytes(), Some(footer))
                .unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);

        let roundtrip = LocalToken::decrypt(&sk, &test.token, Some(footer)).unwrap();
        assert_eq!(roundtrip, message.as_bytes(), "Failed {:?}", test.name);
    }

    fn test_public(test: &PasetoTest) {
        debug_assert!(test.public_key.is_some());
        debug_assert!(test.secret_key.is_some());

        let sk = AsymmetricSecretKey::from(
            &hex::decode(test.secret_key.as_ref().unwrap()).unwrap()[..32],
            Version::V2,
        )
        .unwrap();
        let pk = AsymmetricPublicKey::from(
            &hex::decode(test.public_key.as_ref().unwrap()).unwrap(),
            Version::V2,
        )
        .unwrap();
        let footer = test.footer.as_bytes();

        // payload is null when we expect failure
        if test.expect_fail {
            assert!(PublicToken::verify(&pk, &test.token, Some(footer)).is_err());

            return;
        }

        let message = serde_json::to_string(test.payload.as_ref().unwrap()).unwrap();

        let actual = PublicToken::sign(&sk, &pk, message.as_bytes(), Some(footer)).unwrap();
        assert_eq!(actual, test.token, "Failed {:?}", test.name);
        assert!(
            PublicToken::verify(&pk, &test.token, Some(footer)).is_ok(),
            "Failed {:?}",
            test.name
        );
    }

    #[test]
    fn run_test_vectors() {
        let path = "./test_vectors/v2.json";
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

    const TEST_SK_BYTES: [u8; 32] = [
        180, 203, 251, 67, 223, 76, 226, 16, 114, 125, 149, 62, 74, 113, 51, 7, 250, 25, 187, 125,
        159, 133, 4, 20, 56, 217, 225, 27, 148, 42, 55, 116,
    ];

    const TEST_PK_BYTES: [u8; 32] = [
        30, 185, 219, 187, 188, 4, 124, 3, 253, 112, 96, 78, 0, 113, 240, 152, 126, 22, 178, 139,
        117, 114, 37, 193, 31, 0, 65, 93, 14, 32, 177, 162,
    ];

    const MESSAGE: &'static str =
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
    const FOOTER: &'static str = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const VALID_PUBLIC_TOKEN: &'static str = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
    const VALID_LOCAL_TOKEN: &'static str = "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    #[test]
    fn test_roundtrip_local() {
        let sk = SymmetricKey::gen(Version::V2).unwrap();

        let token = LocalToken::encrypt(&sk, MESSAGE.as_bytes(), None).unwrap();
        let payload = LocalToken::decrypt(&sk, &token, None).unwrap();

        assert_eq!(payload, MESSAGE.as_bytes());
    }

    #[test]
    fn test_roundtrip_public() {
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V2).unwrap();
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();

        let token = PublicToken::sign(&test_sk, &test_pk, MESSAGE.as_bytes(), None).unwrap();
        assert!(PublicToken::verify(&test_pk, &token, None).is_ok());
    }

    #[test]
    fn footer_none_some_empty_is_same() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V2).unwrap();
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let message =
            b"{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
        let footer = b"";

        let actual_some = PublicToken::sign(&test_sk, &test_pk, message, Some(footer)).unwrap();
        let actual_none = PublicToken::sign(&test_sk, &test_pk, message, None).unwrap();
        assert_eq!(actual_some, actual_none);

        assert!(PublicToken::verify(&test_pk, &actual_none, Some(footer)).is_ok());
        assert!(PublicToken::verify(&test_pk, &actual_some, None).is_ok());

        let actual_some = LocalToken::encrypt(&test_local_sk, message, Some(footer)).unwrap();
        let actual_none = LocalToken::encrypt(&test_local_sk, message, None).unwrap();
        // They don't equal because the nonce is random. So we only check decryption.

        assert!(LocalToken::decrypt(&test_local_sk, &actual_none, Some(footer)).is_ok());
        assert!(LocalToken::decrypt(&test_local_sk, &actual_some, None).is_ok());
    }

    #[test]
    // NOTE: Official test vectors do not seem to include this.
    fn empty_payload() {
        todo!();
    }

    #[test]
    // NOTE: "Algorithm lucidity" from spec.
    fn wrong_key_version() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V4).unwrap();
        let test_sk = AsymmetricSecretKey::from(&TEST_SK_BYTES, Version::V4).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V4).unwrap();

        assert_eq!(
            PublicToken::sign(&test_sk, &test_pk, b"test", None).unwrap_err(),
            Errors::KeyError
        );
        assert_eq!(
            PublicToken::verify(&test_pk, "test", None).unwrap_err(),
            Errors::KeyError
        );
        assert_eq!(
            LocalToken::encrypt(&test_local_sk, b"test", None).unwrap_err(),
            Errors::KeyError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, "test", None).unwrap_err(),
            Errors::KeyError
        );
    }

    #[test]
    fn err_on_modified_header() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("v2", "v1"),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("v2", "v1"),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("v2", ""),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("v2", ""),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    fn err_on_modified_purpose() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("public", "local"),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("local", "public"),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN.replace("public", ""),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN.replace("local", ""),
                Some(FOOTER.as_bytes())
            )
            .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    // NOTE: Missing but created with one
    fn err_on_missing_payload() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        split_public[2] = "";
        let invalid_public: String = split_public.iter().map(|x| *x).collect();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        split_local[2] = "";
        let invalid_local: String = split_local.iter().map(|x| *x).collect();

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes())).unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, &invalid_local, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    fn err_on_extra_after_footer() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        let mut split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        split_public.push(".shouldNotBeHere");
        let invalid_public: String = split_public.iter().map(|x| *x).collect();

        let mut split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        split_local.push(".shouldNotBeHere");
        let invalid_local: String = split_local.iter().map(|x| *x).collect();

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes())).unwrap_err(),
            Errors::TokenFormatError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, &invalid_local, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenFormatError
        );
    }

    #[test]
    fn err_on_modified_footer() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        assert_eq!(
            PublicToken::verify(
                &test_pk,
                &VALID_PUBLIC_TOKEN,
                Some(&FOOTER.replace("kid", "mid").as_bytes())
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
        assert_eq!(
            LocalToken::decrypt(
                &test_local_sk,
                &VALID_LOCAL_TOKEN,
                Some(&FOOTER.replace("kid", "mid").as_bytes())
            )
            .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_footer_in_token_none_supplied() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        assert_eq!(
            PublicToken::verify(&test_pk, &VALID_PUBLIC_TOKEN, Some(b"")).unwrap_err(),
            Errors::TokenValidationError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, &VALID_LOCAL_TOKEN, Some(b"")).unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_no_footer_in_token_some_supplied() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

        let split_public = VALID_PUBLIC_TOKEN.split('.').collect::<Vec<&str>>();
        let invalid_public: String = format!(
            "{}.{}.{}",
            split_public[0], split_public[1], split_public[2]
        );

        let split_local = VALID_LOCAL_TOKEN.split('.').collect::<Vec<&str>>();
        let invalid_local: String =
            format!("{}.{}.{}", split_local[0], split_local[1], split_local[2]);

        assert_eq!(
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes())).unwrap_err(),
            Errors::TokenValidationError
        );
        assert_eq!(
            LocalToken::decrypt(&test_local_sk, &invalid_local, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_signature() {
        let test_pk = AsymmetricPublicKey::from(&TEST_PK_BYTES, Version::V2).unwrap();

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
            PublicToken::verify(&test_pk, &invalid_public, Some(FOOTER.as_bytes())).unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_tag() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

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
            LocalToken::decrypt(&test_local_sk, &invalid_local, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_ciphertext() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

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
            LocalToken::decrypt(&test_local_sk, &invalid_local, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_modified_nonce() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

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
            LocalToken::decrypt(&test_local_sk, &invalid_local, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_invalid_base64() {
        let test_local_sk = SymmetricKey::from(&TEST_SK_BYTES, Version::V2).unwrap();

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
            LocalToken::decrypt(&test_local_sk, &invalid_local, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_invalid_public_secret_key() {
        let bad_pk = AsymmetricPublicKey::from(&[0u8; 32], Version::V2).unwrap();

        assert_eq!(
            PublicToken::verify(&bad_pk, VALID_PUBLIC_TOKEN, Some(FOOTER.as_bytes())).unwrap_err(),
            Errors::TokenValidationError
        );
    }

    #[test]
    fn err_on_invalid_shared_secret_key() {
        let bad_local_sk = SymmetricKey::from(&[0u8; 32], Version::V2).unwrap();

        assert_eq!(
            LocalToken::decrypt(&bad_local_sk, VALID_LOCAL_TOKEN, Some(FOOTER.as_bytes()))
                .unwrap_err(),
            Errors::TokenValidationError
        );
    }
}
