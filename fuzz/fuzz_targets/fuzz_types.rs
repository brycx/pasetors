#![no_main]
extern crate pasetors;

use core::convert::TryFrom;
use libfuzzer_sys::fuzz_target;
use pasetors::claims::*;
use pasetors::token::UntrustedToken;
use pasetors::{Local, Public, V2, V3, V4};
use pasetors::footer::Footer;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed_claims) = Claims::from_bytes(data) {
        assert!(parsed_claims.to_string().is_ok());
    }

    let mut footer = Footer::new();
    if let Ok(()) = footer.parse_bytes(data) {
        assert!(footer.to_string().is_ok());
    }

    let message: String = String::from_utf8_lossy(data).into();

    if let Ok(untrusted_v2_public) = UntrustedToken::<Public, V2>::try_from(message.as_str()) {
        assert!(!untrusted_v2_public.untrusted_message().is_empty());
        assert!(!untrusted_v2_public.untrusted_payload().is_empty());
    }
    if let Ok(untrusted_v2_local) = UntrustedToken::<Local, V2>::try_from(message.as_str()) {
        assert!(!untrusted_v2_local.untrusted_message().is_empty());
        assert!(!untrusted_v2_local.untrusted_payload().is_empty());
    }
    if let Ok(untrusted_v3_public) = UntrustedToken::<Public, V3>::try_from(message.as_str()) {
        assert!(!untrusted_v3_public.untrusted_message().is_empty());
        assert!(!untrusted_v3_public.untrusted_payload().is_empty());
    }
    if let Ok(untrusted_v3_local) = UntrustedToken::<Local, V3>::try_from(message.as_str()) {
        assert!(!untrusted_v3_local.untrusted_message().is_empty());
        assert!(!untrusted_v3_local.untrusted_payload().is_empty());
    }
    if let Ok(untrusted_v4_public) = UntrustedToken::<Public, V4>::try_from(message.as_str()) {
        assert!(!untrusted_v4_public.untrusted_message().is_empty());
        assert!(!untrusted_v4_public.untrusted_payload().is_empty());
    }
    if let Ok(untrusted_v4_local) = UntrustedToken::<Local, V4>::try_from(message.as_str()) {
        assert!(!untrusted_v4_local.untrusted_message().is_empty());
        assert!(!untrusted_v4_local.untrusted_payload().is_empty());
    }
});
