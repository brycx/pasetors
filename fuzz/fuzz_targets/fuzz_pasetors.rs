#![no_main]
extern crate ed25519_dalek;
extern crate pasetors;
extern crate rand_chacha;
extern crate rand_core;

use libfuzzer_sys::fuzz_target;

use ed25519_dalek::Keypair;
use pasetors::claims::*;
use pasetors::keys::*;
use pasetors::{version2, version4};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn fuzztest_v2(data: &[u8], csprng: &mut ChaCha20Rng) {
    let keypair: Keypair = Keypair::generate(csprng);
    let sk = AsymmetricSecretKey::<V2>::from(&keypair.secret.to_bytes()).unwrap();
    let pk = AsymmetricPublicKey::<V2>::from(&keypair.public.to_bytes()).unwrap();
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let sk_local = SymmetricKey::<V2>::from(&key).unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return;
    }

    // Public
    if version2::PublicToken::verify(&pk, &message, None).is_ok() {
        panic!("Invalid token was verified with version 2");
    }
    let public_token = version2::PublicToken::sign(&sk, &pk, message.as_bytes(), None).unwrap();
    if version2::PublicToken::verify(&pk, &public_token, None).is_err() {
        panic!("Valid token was NOT verified with version 2");
    }
    // Local
    if version2::LocalToken::decrypt(&sk_local, &message, None).is_ok() {
        panic!("Invalid token was verified with version 2");
    }

    let local_token = version2::LocalToken::encrypt(&sk_local, message.as_bytes(), None).unwrap();
    if version2::LocalToken::decrypt(&sk_local, &local_token, None).is_err() {
        panic!("Valid token was NOT verified with version 2");
    }
}

fn fuzztest_v4(data: &[u8], csprng: &mut ChaCha20Rng) {
    let keypair: Keypair = Keypair::generate(csprng);
    let sk = AsymmetricSecretKey::<V4>::from(&keypair.secret.to_bytes()).unwrap();
    let pk = AsymmetricPublicKey::<V4>::from(&keypair.public.to_bytes()).unwrap();
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let sk_local = SymmetricKey::<V4>::from(&key).unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return;
    }

    // Public
    if version4::PublicToken::verify(&pk, &message, None, None).is_ok() {
        panic!("Invalid token was verified with version 4");
    }
    let public_token =
        version4::PublicToken::sign(&sk, &pk, message.as_bytes(), None, None).unwrap();
    if version4::PublicToken::verify(&pk, &public_token, None, None).is_err() {
        panic!("Valid token was NOT verified with version 4");
    }
    // Local
    if version4::LocalToken::decrypt(&sk_local, &message, None, None).is_ok() {
        panic!("Invalid token was verified with version 4");
    }

    let local_token =
        version4::LocalToken::encrypt(&sk_local, message.as_bytes(), None, None).unwrap();
    if version4::LocalToken::decrypt(&sk_local, &local_token, None, None).is_err() {
        panic!("Valid token was NOT verified with version 4");
    }
}

fn fuzz_highlevel(data: &[u8], csprng: &mut ChaCha20Rng) {
    let keypair: Keypair = Keypair::generate(csprng);
    let sk = AsymmetricSecretKey::<V4>::from(&keypair.secret.to_bytes()).unwrap();
    let pk = AsymmetricPublicKey::<V4>::from(&keypair.public.to_bytes()).unwrap();
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let sk_local = SymmetricKey::<V4>::from(&key).unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return;
    }

    let mut claims = Claims::new().unwrap();
    claims.add_additional("data", message).unwrap();
    claims.subject("test").unwrap();
    let validation_rules = ClaimsValidationRules::new();

    let public_token = pasetors::public::sign(&sk, &pk, &claims, None, None).unwrap();
    if let Ok(claims_from) =
        pasetors::public::verify(&pk, &public_token, &validation_rules, None, None)
    {
        assert_eq!(claims, claims_from);
    } else {
        panic!("(high-level API): Valid token was NOT verified with version 4");
    }

    let local_token = pasetors::local::encrypt(&sk_local, &claims, None, None).unwrap();
    if let Ok(claims_from) =
        pasetors::local::decrypt(&sk_local, &local_token, &validation_rules, None, None)
    {
        assert_eq!(claims, claims_from);
    } else {
        panic!("(high-level API): Valid token was NOT verified with version 4");
    }
}

fn fuzz_paserk(data: &[u8]) {
    use core::convert::TryFrom;
    use pasetors::paserk::FormatAsPaserk;

    let data: String = String::from_utf8_lossy(data).into();

    if let Ok(valid_paserk) = AsymmetricKeyPair::<V2>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
    }
    if let Ok(valid_paserk) = AsymmetricKeyPair::<V4>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
    }

    if let Ok(valid_paserk) = AsymmetricPublicKey::<V2>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
    }
    if let Ok(valid_paserk) = AsymmetricPublicKey::<V4>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
    }

    if let Ok(valid_paserk) = SymmetricKey::<V2>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
    }
    if let Ok(valid_paserk) = SymmetricKey::<V4>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut csprng = rand_chacha::ChaCha20Rng::seed_from_u64(123456789u64);

    fuzztest_v2(data, &mut csprng);
    fuzztest_v4(data, &mut csprng);
    fuzz_highlevel(data, &mut csprng);
    fuzz_paserk(data);

    if let Ok(parsed_claims) = Claims::from_bytes(data) {
        assert!(parsed_claims.to_string().is_ok());
    }
});
