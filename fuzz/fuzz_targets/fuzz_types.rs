#![no_main]
extern crate pasetors;

use core::convert::TryFrom;
use libfuzzer_sys::fuzz_target;
use pasetors::claims::*;
use pasetors::token::UntrustedToken;
use pasetors::{V2, V3, V4};

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed_claims) = Claims::from_bytes(data) {
        assert!(parsed_claims.to_string().is_ok());
    }

    let message: String = String::from_utf8_lossy(data).into();

    if let Ok(untrusted_v2) = UntrustedToken::<V2>::try_from(message.as_str()) {
        assert!(!untrusted_v2.untrusted_header().is_empty());
        assert!(!untrusted_v2.untrusted_message().is_empty());
        assert!(!untrusted_v2.untrusted_payload().is_empty());
    }
    if let Ok(untrusted_v3) = UntrustedToken::<V3>::try_from(message.as_str()) {
        assert!(!untrusted_v3.untrusted_header().is_empty());
        assert!(!untrusted_v3.untrusted_message().is_empty());
        assert!(!untrusted_v3.untrusted_payload().is_empty());
    }
    if let Ok(untrusted_v4) = UntrustedToken::<V4>::try_from(message.as_str()) {
        assert!(!untrusted_v4.untrusted_header().is_empty());
        assert!(!untrusted_v4.untrusted_message().is_empty());
        assert!(!untrusted_v4.untrusted_payload().is_empty());
    }
});
