#![no_main]
extern crate ed25519_dalek;
extern crate pasetors;
extern crate rand_chacha;
extern crate rand_core;

use libfuzzer_sys::fuzz_target;

use pasetors::{version2, version4};
use pasetors::keys::*;
use pasetors::claims::*;
use ed25519_dalek::Keypair;
use rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;


fn fuzztest(data: &[u8], csprng: &mut ChaCha20Rng, version: Version) {
    let keypair: Keypair = Keypair::generate(csprng);
    let sk = AsymmetricSecretKey::from(&keypair.secret.to_bytes(), version).unwrap();
    let pk = AsymmetricPublicKey::from(&keypair.public.to_bytes(), version).unwrap();
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let sk_local = SymmetricKey::from(&key, version).unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return
    }

    match version {
        Version::V2 => {
            // Public
            if !version2::PublicToken::verify(&pk, &message, None).is_err() {
                panic!("Invalid token was verified with version 2");
            }
            let public_token =
                version2::PublicToken::sign(&sk, &pk, message.as_bytes(), None).unwrap();
            if !version2::PublicToken::verify(&pk, &public_token, None).is_ok() {
                panic!("Valid token was NOT verified with version 2");
            }
            // Local
            if !version2::LocalToken::decrypt(&sk_local, &message, None).is_err() {
                panic!("Invalid token was verified with version 2");
            }

            let local_token =
                version2::LocalToken::encrypt(&sk_local, message.as_bytes(), None).unwrap();
            if !version2::LocalToken::decrypt(&sk_local, &local_token, None).is_ok() {
                panic!("Valid token was NOT verified with version 2");
            }
        }
        Version::V4 => {
            // Public
            if !version4::PublicToken::verify(&pk, &message, None, None).is_err() {
                panic!("Invalid token was verified with version 4");
            }
            let public_token =
                version4::PublicToken::sign(&sk, &pk, message.as_bytes(), None, None).unwrap();
            if !version4::PublicToken::verify(&pk, &public_token, None, None).is_ok() {
                panic!("Valid token was NOT verified with version 4");
            }
            // Local
            if !version4::LocalToken::decrypt(&sk_local, &message, None, None).is_err() {
                panic!("Invalid token was verified with version 4");
            }

            let local_token =
                version4::LocalToken::encrypt(&sk_local, message.as_bytes(), None, None).unwrap();
            if !version4::LocalToken::decrypt(&sk_local, &local_token, None, None).is_ok() {
                panic!("Valid token was NOT verified with version 4");
            }
        }
    }
}

fn fuzz_highlevel(data: &[u8], csprng: &mut ChaCha20Rng) {
    let keypair: Keypair = Keypair::generate(csprng);
    let sk = AsymmetricSecretKey::from(&keypair.secret.to_bytes(), Version::V4).unwrap();
    let pk = AsymmetricPublicKey::from(&keypair.public.to_bytes(), Version::V4).unwrap();
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let sk_local = SymmetricKey::from(&key, Version::V4).unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return
    }

    let mut claims = Claims::new().unwrap();
    claims.add_additional("data", message).unwrap();
    claims.subject("test").unwrap();
    let validation_rules = ClaimsValidationRules::new();

    let public_token =
        pasetors::public::sign(&sk, &pk, &claims, None, None).unwrap();
    if !pasetors::public::verify(&pk, &public_token, &validation_rules, None, None).is_ok() {
        panic!("Valid token was NOT verified with version 4");
    }

    let local_token =
        pasetors::local::encrypt(&sk_local,&claims, None, None).unwrap();
    if !pasetors::local::decrypt(&sk_local, &local_token, &validation_rules, None, None).is_ok() {
        panic!("Valid token was NOT verified with version 4");
    }
}

fuzz_target!(|data: &[u8]| {

    let mut csprng = rand_chacha::ChaCha20Rng::seed_from_u64(123456789u64);

    fuzztest(data, &mut csprng, Version::V2);
    fuzztest(data, &mut csprng, Version::V4);
    fuzz_highlevel(data, &mut csprng);
});
