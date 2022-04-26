#![no_main]
extern crate ed25519_compact;
extern crate pasetors;
extern crate rand_chacha;
extern crate rand_core;

use libfuzzer_sys::fuzz_target;

use core::convert::TryFrom;
use ed25519_compact::{KeyPair, Seed};
use pasetors::claims::*;
use pasetors::keys::*;
use pasetors::token::UntrustedToken;
use pasetors::{version2, version3, version4};
use pasetors::{Local, Public, V2, V3, V4};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn fuzztest_v2(data: &[u8], csprng: &mut ChaCha20Rng) {
    let mut seed_bytes = [0u8; 32];
    csprng.fill_bytes(&mut seed_bytes);
    let seed = Seed::from_slice(&seed_bytes).unwrap();
    let keypair: KeyPair = KeyPair::from_seed(seed);
    let sk = AsymmetricSecretKey::<V2>::from(&keypair.sk[..32]).unwrap();
    let pk = AsymmetricPublicKey::<V2>::from(keypair.pk.as_ref()).unwrap();
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let sk_local = SymmetricKey::<V2>::from(&key).unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return;
    }

    // Public
    if let Ok(untrusted) = UntrustedToken::<Public, V2>::try_from(&message) {
        if version2::PublicToken::verify(&pk, &untrusted, None).is_ok() {
            panic!("Invalid token was verified with version 2");
        }
    }

    let public_token = UntrustedToken::<Public, V2>::try_from(
        &version2::PublicToken::sign(&sk, &pk, message.as_bytes(), None).unwrap(),
    )
    .unwrap();
    match version2::PublicToken::verify(&pk, &public_token, None) {
        Ok(trusted) => {
            assert_eq!(trusted.payload(), message);
            assert!(trusted.footer().is_empty());
            assert!(trusted.implicit_assert().is_empty());
        }
        Err(_) => panic!("Valid token was NOT verified with version 2"),
    };

    // Local
    if let Ok(untrusted) = UntrustedToken::<Local, V2>::try_from(&message) {
        if version2::LocalToken::decrypt(&sk_local, &untrusted, None).is_ok() {
            panic!("Invalid token was verified with version 2");
        }
    }

    let local_token = UntrustedToken::<Local, V2>::try_from(
        &version2::LocalToken::encrypt(&sk_local, message.as_bytes(), None).unwrap(),
    )
    .unwrap();
    match version2::LocalToken::decrypt(&sk_local, &local_token, None) {
        Ok(trusted) => {
            assert_eq!(trusted.payload(), message);
            assert!(trusted.footer().is_empty());
            assert!(trusted.implicit_assert().is_empty());
        }
        Err(_) => panic!("Valid token was NOT verified with version 2"),
    };
}

fn fuzztest_v3(data: &[u8]) {
    // *ring* keypair must be randomly generated. No way to seed it from their API.
    let kp = AsymmetricKeyPair::<V3>::generate().unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return;
    }

    // Public
    if let Ok(untrusted) = UntrustedToken::<Public, V3>::try_from(&message) {
        if version3::PublicToken::verify(&kp.public, &untrusted, None, None).is_ok() {
            panic!("Invalid token was verified with version 3");
        }
    }

    let public_token = UntrustedToken::<Public, V3>::try_from(
        &version3::PublicToken::sign(&kp.secret, &kp.public, message.as_bytes(), None, None)
            .unwrap(),
    )
    .unwrap();
    match version3::PublicToken::verify(&kp.public, &public_token, None, None) {
        Ok(trusted) => {
            assert_eq!(trusted.payload(), message);
            assert!(trusted.footer().is_empty());
            assert!(trusted.implicit_assert().is_empty());
        }
        Err(_) => panic!("Valid token was NOT verified with version 3"),
    };
}

fn fuzztest_v4(data: &[u8], csprng: &mut ChaCha20Rng) {
    let mut seed_bytes = [0u8; 32];
    csprng.fill_bytes(&mut seed_bytes);
    let seed = Seed::from_slice(&seed_bytes).unwrap();
    let keypair: KeyPair = KeyPair::from_seed(seed);
    let sk = AsymmetricSecretKey::<V4>::from(&keypair.sk[..32]).unwrap();
    let pk = AsymmetricPublicKey::<V4>::from(keypair.pk.as_ref()).unwrap();
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    let sk_local = SymmetricKey::<V4>::from(&key).unwrap();
    let message: String = String::from_utf8_lossy(data).into();
    if message.is_empty() {
        return;
    }

    // Public
    if let Ok(untrusted) = UntrustedToken::<Public, V4>::try_from(&message) {
        if version4::PublicToken::verify(&pk, &untrusted, None, None).is_ok() {
            panic!("Invalid token was verified with version 4");
        }
    }

    let public_token = UntrustedToken::<Public, V4>::try_from(
        &version4::PublicToken::sign(&sk, &pk, message.as_bytes(), None, None).unwrap(),
    )
    .unwrap();
    match version4::PublicToken::verify(&pk, &public_token, None, None) {
        Ok(trusted) => {
            assert_eq!(trusted.payload(), message);
            assert!(trusted.footer().is_empty());
            assert!(trusted.implicit_assert().is_empty());
        }
        Err(_) => panic!("Valid token was NOT verified with version 4"),
    };
    // Local
    if let Ok(untrusted) = UntrustedToken::<Local, V4>::try_from(&message) {
        if version4::LocalToken::decrypt(&sk_local, &untrusted, None, None).is_ok() {
            panic!("Invalid token was verified with version 4");
        }
    }

    let local_token = UntrustedToken::<Local, V4>::try_from(
        &version4::LocalToken::encrypt(&sk_local, message.as_bytes(), None, None).unwrap(),
    )
    .unwrap();
    match version4::LocalToken::decrypt(&sk_local, &local_token, None, None) {
        Ok(trusted) => {
            assert_eq!(trusted.payload(), message);
            assert!(trusted.footer().is_empty());
            assert!(trusted.implicit_assert().is_empty());
        }
        Err(_) => panic!("Valid token was NOT verified with version 4"),
    };
}

fn fuzz_highlevel(data: &[u8], csprng: &mut ChaCha20Rng) {
    let mut seed_bytes = [0u8; 32];
    csprng.fill_bytes(&mut seed_bytes);
    let seed = Seed::from_slice(&seed_bytes).unwrap();
    let keypair: KeyPair = KeyPair::from_seed(seed);
    let sk = AsymmetricSecretKey::<V4>::from(&keypair.sk[..32]).unwrap();
    let pk = AsymmetricPublicKey::<V4>::from(keypair.pk.as_ref()).unwrap();
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

    let public_token = UntrustedToken::<Public, V4>::try_from(
        &pasetors::public::sign(&sk, &pk, &claims, None, None).unwrap(),
    )
    .unwrap();
    if let Ok(trusted_token) =
        pasetors::public::verify(&pk, &public_token, &validation_rules, None, None)
    {
        assert_eq!(&claims, trusted_token.payload_claims().unwrap());
    } else {
        panic!("(high-level API): Valid token was NOT verified with version 4");
    }

    let local_token = UntrustedToken::<Local, V4>::try_from(
        &pasetors::local::encrypt(&sk_local, &claims, None, None).unwrap(),
    )
    .unwrap();
    if let Ok(trusted_token) =
        pasetors::local::decrypt(&sk_local, &local_token, &validation_rules, None, None)
    {
        assert_eq!(&claims, trusted_token.payload_claims().unwrap());
    } else {
        panic!("(high-level API): Valid token was NOT verified with version 4");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut csprng = rand_chacha::ChaCha20Rng::seed_from_u64(123456789u64);

    fuzztest_v2(data, &mut csprng);
    fuzztest_v3(data);
    fuzztest_v4(data, &mut csprng);
    fuzz_highlevel(data, &mut csprng);
});
