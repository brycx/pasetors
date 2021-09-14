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
use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;

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

        let mut n = [0u8; 32];
        getrandom::getrandom(&mut n)?;

        Self::encrypt_with_nonce(secret_key, &n, message, footer, implicit_assert)
    }

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

        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);
        let parts_split = validate_format_footer(Self::HEADER, token, f)?;

        let nc = decode_b64(parts_split[2])?;
        if nc.len() < (XCHACHA_NONCESIZE + Self::TAG_LEN) {
            return Err(Errors::TokenFormatError);
        }
        let mut n: [u8; 32] = [0u8; 32];
        n.copy_from_slice(nc[..32].as_ref());
        let c = nc[n.len()..nc.len() - 32].as_ref();
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
mod test_local {

    use super::LocalToken;
    use hex;

    use super::*;
    use std::fs::File;
    use std::io::BufReader;

    use crate::keys::Version;
    use serde::{Deserialize, Serialize};

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    struct TestFile {
        name: String,
        tests: Vec<PasetoTest>,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    struct PasetoTest {
        name: String,
        key: Option<String>,
        nonce: Option<String>,
        #[serde(rename(deserialize = "public-key"))]
        public_key: Option<String>,
        #[serde(rename(deserialize = "secret-key"))]
        secret_key: Option<String>,
        #[serde(rename(deserialize = "public-key-pem"))]
        public_key_pem: Option<String>,
        #[serde(rename(deserialize = "secret-key-pem"))]
        secret_key_pem: Option<String>,
        token: String,
        payload: Payload,
        footer: String,
        #[serde(rename(deserialize = "implicit-assertion"))]
        implicit_assertion: String,
    }

    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize, Debug)]
    struct Payload {
        data: String,
        exp: String,
    }

    fn test_local(test: &PasetoTest) {
        debug_assert!(test.nonce.is_some());
        debug_assert!(test.key.is_some());

        let sk = SymmetricKey::from(
            &hex::decode(test.key.as_ref().unwrap()).unwrap(),
            Version::V4,
        )
        .unwrap();
        let message = serde_json::to_string(&test.payload).unwrap();
        let nonce = hex::decode(test.nonce.as_ref().unwrap()).unwrap();
        let footer = test.footer.as_bytes();
        let implicit_assert = test.implicit_assertion.as_bytes();

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
        let message = serde_json::to_string(&test.payload).unwrap();
        let footer = test.footer.as_bytes();
        let implicit_assert = test.implicit_assertion.as_bytes();

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
        let path = "./src/v4.json";
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

    #[test]
    fn test_roundtrip_local() {
        let sk = SymmetricKey::gen(Version::V4).unwrap();
        let message = b"token payload";

        let token = LocalToken::encrypt(&sk, message, None, None).unwrap();
        let payload = LocalToken::decrypt(&sk, &token, None, None).unwrap();

        assert_eq!(payload, message);
    }
}
