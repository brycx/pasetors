#![no_main]

extern crate pasetors;
extern crate ring;

use libfuzzer_sys::fuzz_target;

use core::convert::TryFrom;
use pasetors::keys::*;
use pasetors::version3::UncompressedPublicKey;
use ring::signature::{
    EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};

fuzz_target!(|data: &[u8]| {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8_bytes.as_ref()).unwrap();

    let sig = key_pair.sign(&rng, data).unwrap();
    let ring_uncompressed = key_pair.public_key();

    let this_uncompressed = UncompressedPublicKey::try_from(ring_uncompressed.as_ref()).unwrap();
    assert_eq!(ring_uncompressed.as_ref(), &this_uncompressed.0);
    let this_compressed = AsymmetricPublicKey::<V3>::try_from(&this_uncompressed).unwrap();
    let this_round_uncompressed = UncompressedPublicKey::try_from(&this_compressed).unwrap();
    assert_eq!(ring_uncompressed.as_ref(), &this_round_uncompressed.0);

    let unparsed_pk = UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, &this_round_uncompressed.0);
    unparsed_pk.verify(data, sig.as_ref()).unwrap();

    // Fuzz also parsing of random bytes, to also get errors.
    if let Ok(compressed_pk) = AsymmetricPublicKey::<V3>::from(data) {
        if let Ok(uncompressed) = UncompressedPublicKey::try_from(&compressed_pk) {
            assert_eq!(
                AsymmetricPublicKey::<V3>::try_from(&uncompressed)
                    .unwrap()
                    .as_bytes(),
                compressed_pk.as_bytes()
            );
        }
    }
});
