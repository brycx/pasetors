#![no_main]
extern crate pasetors;

use core::convert::TryFrom;
use libfuzzer_sys::fuzz_target;
use pasetors::keys::*;
use pasetors::paserk::{FormatAsPaserk, Id};
use pasetors::{V2, V3, V4};

fuzz_target!(|data: &[u8]| {
    let data: String = String::from_utf8_lossy(data).into();

    if let Ok(valid_paserk) = AsymmetricKeyPair::<V2>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }
    if let Ok(valid_paserk) = AsymmetricSecretKey::<V3>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }
    if let Ok(valid_paserk) = AsymmetricKeyPair::<V4>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }

    if let Ok(valid_paserk) = AsymmetricPublicKey::<V2>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }
    if let Ok(valid_paserk) = AsymmetricPublicKey::<V3>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }
    if let Ok(valid_paserk) = AsymmetricPublicKey::<V4>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }

    if let Ok(valid_paserk) = SymmetricKey::<V2>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }
    if let Ok(valid_paserk) = SymmetricKey::<V4>::try_from(data.clone()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let _ = Id::from(&valid_paserk);
    }
});
