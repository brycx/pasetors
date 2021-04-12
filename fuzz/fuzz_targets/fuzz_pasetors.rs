#![no_main]
extern crate ed25519_dalek;
extern crate pasetors;
extern crate rand_chacha;
extern crate rand_core;

use libfuzzer_sys::fuzz_target;

use pasetors::version2;

use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;

use rand_core::{RngCore, SeedableRng};

fuzz_target!(|data: &[u8]| {
    let mut csprng = rand_chacha::ChaCha20Rng::seed_from_u64(123456789u64);

    // PublicToken
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let pk: PublicKey = keypair.public;
    let message: String = String::from_utf8_lossy(data).into();

    if !version2::PublicToken::verify(pk.as_ref(), &message, None).is_err() {
        panic!("Invalid token was verified");
    }

    let sk: SecretKey = keypair.secret;
    let public_token =
        version2::PublicToken::sign(sk.as_ref(), pk.as_ref(), message.as_bytes(), None).unwrap();
    if !version2::PublicToken::verify(pk.as_ref(), &public_token, None).is_ok() {
        panic!("Valid token was NOT verified");
    }

    // LocalToken
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);

    if !version2::LocalToken::decrypt(key.as_ref(), &message, None).is_err() {
        panic!("Invalid token was verified");
    }

    let local_token =
        version2::LocalToken::encrypt(key.as_ref(), message.as_bytes(), None).unwrap();
    if !version2::LocalToken::decrypt(key.as_ref(), &local_token, None).is_ok() {
        panic!("Valid token was NOT verified");
    }
});
