#![cfg_attr(docsrs, doc(cfg(feature = "v5")))]

//! This is an implementation of the [version 5 specification of PASETO](TODO).

use crate::errors::Error;
use crate::keys::{
    AsymmetricKeyPair, AsymmetricPublicKey, AsymmetricSecretKey, Generate, SymmetricKey,
};
use crate::pae;
use crate::token::{Local, Public, TrustedToken, UntrustedToken};
use crate::version::private::Version;
use core::marker::PhantomData;

use crate::common::{encode_b64, validate_footer_untrusted_token};
use aes::cipher::{KeyIvInit, StreamCipher};

use orion::hazardous::kdf::hkdf;
use orion::hazardous::mac::hmac::sha384::{HmacSha384, SecretKey as MacKey, Tag};
use zeroize::Zeroizing;

type Aes256Ctr128LE = ctr::Ctr128LE<aes::Aes256>;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Version 5 of the PASETO spec.
pub struct V5;

impl Version for V5 {
    const LOCAL_KEY: usize = 32;
    const SECRET_KEY: usize = 32 + Self::PUBLIC_KEY; // TODO!
    const PUBLIC_KEY: usize = 32; // TODO!
    const PUBLIC_SIG: usize = 64; // TODO!
    const LOCAL_NONCE: usize = 32;
    const LOCAL_TAG: usize = 48;
    const PUBLIC_HEADER: &'static str = "v5.public.";
    const LOCAL_HEADER: &'static str = "v5.local.";
    #[cfg(feature = "paserk")]
    const PASERK_ID: usize = 44; // TODO!

    fn validate_local_key(key_bytes: &[u8]) -> Result<(), Error> {
        if key_bytes.len() != Self::LOCAL_KEY {
            return Err(Error::Key);
        }

        Ok(())
    }

    fn validate_secret_key(key_bytes: &[u8]) -> Result<(), Error> {
        todo!();
    }

    fn validate_public_key(key_bytes: &[u8]) -> Result<(), Error> {
        todo!();
    }
}

impl Generate<AsymmetricKeyPair<V5>, V5> for AsymmetricKeyPair<V5> {
    fn generate() -> Result<AsymmetricKeyPair<V5>, Error> {
        todo!();
    }
}

impl Generate<SymmetricKey<V5>, V5> for SymmetricKey<V5> {
    fn generate() -> Result<SymmetricKey<V5>, Error> {
        let mut rng_bytes = vec![0u8; V5::LOCAL_KEY];
        V5::validate_local_key(&rng_bytes)?;
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
    /// The header and purpose for the public token: `v5.public.`.
    pub const HEADER: &'static str = "v5.public.";

    /// Create a public token.
    pub fn sign(
        secret_key: &AsymmetricSecretKey<V5>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        todo!();
    }

    /// Verify a public token.
    ///
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn verify(
        public_key: &AsymmetricPublicKey<V5>,
        token: &UntrustedToken<Public, V5>,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        todo!();
    }
}

/// PASETO v5 local tokens.
pub struct LocalToken;

impl LocalToken {
    /// The header and purpose for the local token: `v5.local.`.
    pub const HEADER: &'static str = "v5.local.";

    /// Domain separator for key-splitting the encryption key (21 in length as bytes).
    const DOMAIN_SEPARATOR_ENC: &'static str = "paseto-encryption-key";

    /// Domain separator for key-splitting the authentication key (24 in length as bytes).
    const DOMAIN_SEPARATOR_AUTH: &'static str = "paseto-auth-key-for-aead";

    const M1_LEN: usize = V5::LOCAL_NONCE + Self::DOMAIN_SEPARATOR_ENC.as_bytes().len();
    const M2_LEN: usize = V5::LOCAL_NONCE + Self::DOMAIN_SEPARATOR_AUTH.as_bytes().len();

    /// Split the user-provided secret key into keys used for encryption and authentication.
    fn key_split(sk: &[u8], n: &[u8]) -> Result<(Aes256Ctr128LE, MacKey), Error> {
        debug_assert_eq!(n.len(), V5::LOCAL_NONCE);
        debug_assert_eq!(sk.len(), V5::LOCAL_KEY);

        let mut m1 = [0u8; Self::M1_LEN];
        m1[..21].copy_from_slice(Self::DOMAIN_SEPARATOR_ENC.as_bytes());
        m1[21..].copy_from_slice(n);

        let mut m2 = [0u8; Self::M2_LEN];
        m2[..24].copy_from_slice(Self::DOMAIN_SEPARATOR_AUTH.as_bytes());
        m2[24..].copy_from_slice(n);

        let mut okm_out = [0u8; 48]; // TODO: Make self-zeroizing?
        let mut ek = [0u8; 32]; // TODO: Make self-zeroizing?
        let mut n2 = [0u8; 16];
        let mut ak = [0u8; 32]; // TODO: Make self-zeroizing?

        // NOTE: Should never panic with these hardcoded lengths.
        hkdf::sha512::derive_key(&[], sk, Some(&m1), &mut okm_out).unwrap();
        ek.copy_from_slice(&okm_out[..32]);
        n2.copy_from_slice(&okm_out[32..48]);
        // NOTE: Should never panic with these hardcoded lengths.
        hkdf::sha512::derive_key(&[], sk, Some(&m2), &mut okm_out).unwrap();
        ak.copy_from_slice(&okm_out[..32]);

        let cipher = Aes256Ctr128LE::new(&ek.into(), &n2.into());
        // NOTE: Should never panic with these hardcoded lengths.
        let mk = MacKey::from_slice(&ak).unwrap();

        Ok((cipher, mk))
    }

    /// Encrypt and authenticate a message using nonce directly.
    pub(crate) fn encrypt_with_nonce(
        secret_key: &SymmetricKey<V5>,
        nonce: &[u8],
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        debug_assert_eq!(nonce.len(), V5::LOCAL_NONCE);
        let f = footer.unwrap_or(&[]);
        let i = implicit_assert.unwrap_or(&[]);

        let (mut cipher_ctx, hmac_key) = Self::key_split(secret_key.as_bytes(), nonce)?;
        let mut ciphertext = vec![0u8; message.len()];
        cipher_ctx
            .apply_keystream_b2b(message, &mut ciphertext)
            .map_err(|_| Error::Encryption)?;

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), nonce, ciphertext.as_slice(), f, i])?;
        // NOTE: Creating HMAC key here, like should never panic due to length.
        let mut hmac_ctx = HmacSha384::new(&hmac_key);
        hmac_ctx
            .update(pre_auth.as_slice())
            .map_err(|_| Error::Encryption)?;
        let tag = hmac_ctx.finalize().map_err(|_| Error::Encryption)?;

        // nonce and tag lengths are 32 and 48, so obviously safe to op::add
        let concat_len: usize = match (nonce.len() + tag.len()).checked_add(ciphertext.len()) {
            Some(len) => len,
            None => return Err(Error::Encryption),
        };
        let mut concat = vec![0u8; concat_len];
        concat[..32].copy_from_slice(nonce);
        concat[32..32 + ciphertext.len()].copy_from_slice(ciphertext.as_slice());
        concat[concat_len - V5::LOCAL_TAG..].copy_from_slice(tag.unprotected_as_bytes());

        let token_no_footer = format!("{}{}", Self::HEADER, encode_b64(concat)?);

        if f.is_empty() {
            Ok(token_no_footer)
        } else {
            Ok(format!("{}.{}", token_no_footer, encode_b64(f)?))
        }
    }

    /// Create a local token.
    pub fn encrypt(
        secret_key: &SymmetricKey<V5>,
        message: &[u8],
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<String, Error> {
        if message.is_empty() {
            return Err(Error::EmptyPayload);
        }

        let mut n = [0u8; V5::LOCAL_NONCE];
        getrandom::getrandom(&mut n)?;

        Self::encrypt_with_nonce(secret_key, &n, message, footer, implicit_assert)
    }

    #[allow(clippy::many_single_char_names)] // The single-char names match those in the spec
    /// Verify and decrypt a local token.
    ///
    /// If `footer.is_none()`, then it will be validated but not compared to a known value.
    /// If `footer.is_some()`, then it will be validated AND compared to the known value.
    pub fn decrypt(
        secret_key: &SymmetricKey<V5>,
        token: &UntrustedToken<Local, V5>,
        footer: Option<&[u8]>,
        implicit_assert: Option<&[u8]>,
    ) -> Result<TrustedToken, Error> {
        validate_footer_untrusted_token(token, footer)?;

        let f = token.untrusted_footer();
        let i = implicit_assert.unwrap_or(&[]);
        let nc = token.untrusted_message();

        let mut n: [u8; 32] = [0u8; V5::LOCAL_NONCE];
        n.copy_from_slice(nc[..V5::LOCAL_NONCE].as_ref());
        let c = token.untrusted_payload();
        let t = nc[nc.len() - V5::LOCAL_TAG..].as_ref();

        let (mut cipher_ctx, hmac_key) = Self::key_split(secret_key.as_bytes(), &n)?;

        let pre_auth = pae::pae(&[Self::HEADER.as_bytes(), n.as_ref(), c, f, i])?;
        let expected_tag = Tag::from_slice(t).map_err(|_| Error::TokenValidation)?;
        HmacSha384::verify(&expected_tag, &hmac_key, pre_auth.as_slice())
            .map_err(|_| Error::TokenValidation)?;

        let mut out = vec![0u8; c.len()];
        cipher_ctx
            .apply_keystream_b2b(c, &mut out)
            .map_err(|_| Error::TokenValidation)?;

        TrustedToken::_new(Self::HEADER, &out, f, i)
    }
}
