#![no_main]
extern crate pasetors;
extern crate rand_core;
extern crate rand_chacha;
extern crate ed25519_dalek;

use libfuzzer_sys::fuzz_target;

use pasetors::version2;

use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;

use rand_core::{SeedableRng, RngCore};

fuzz_target!(|data: &[u8]| {

    let mut csprng = rand_chacha::ChaCha20Rng::seed_from_u64(123456789u64); 

    // PublicToken
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let pk: PublicKey = keypair.public;
    let message: String = String::from_utf8_lossy(data).into();

    if !version2::PublicToken::verify(pk, &message, Some("")).is_err() {
        panic!("Invalid token was verified");
    }

    let sk: SecretKey = keypair.secret;
    let public_token = version2::PublicToken::sign(sk, pk, &message, Some("")).unwrap();
    if !version2::PublicToken::verify(pk, &public_token, Some("")).is_ok() {
        panic!("Valid token was NOT verified");
    }

    // LocalToken
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);

    if !version2::LocalToken::decrypt(key, &message, Some("")).is_err() {
        panic!("Invalid token was verified");
    }
    
    let local_token = version2::LocalToken::encrypt(&mut csprng, key, &message, Some("")).unwrap();
    if !version2::LocalToken::decrypt(key, &local_token, Some("")).is_ok() {
        panic!("Valid token was NOT verified");
    }

});
