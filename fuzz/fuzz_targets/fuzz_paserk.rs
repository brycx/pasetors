#![no_main]
extern crate pasetors;

use core::convert::TryFrom;
use libfuzzer_sys::fuzz_target;
use pasetors::keys::*;
use pasetors::paserk::{FormatAsPaserk, Id};
use pasetors::{version2::V2, version3::V3, version4::V4};

fuzz_target!(|data: &[u8]| {
    let data: String = String::from_utf8_lossy(data).into();

    if let Ok(valid_paserk) = AsymmetricSecretKey::<V2>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }
    if let Ok(valid_paserk) = AsymmetricSecretKey::<V3>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }
    if let Ok(valid_paserk) = AsymmetricSecretKey::<V4>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }

    if let Ok(valid_paserk) = AsymmetricPublicKey::<V2>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }
    if let Ok(valid_paserk) = AsymmetricPublicKey::<V3>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }
    if let Ok(valid_paserk) = AsymmetricPublicKey::<V4>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }

    if let Ok(valid_paserk) = SymmetricKey::<V2>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }
    if let Ok(valid_paserk) = SymmetricKey::<V4>::try_from(data.as_str()) {
        let mut buf = String::new();
        valid_paserk.fmt(&mut buf).unwrap();
        assert_eq!(&data, &buf);
        let id_from_key = Id::from(&valid_paserk);
        let mut buf = String::new();
        id_from_key.fmt(&mut buf).unwrap();
        let id_from_string = Id::try_from(buf.as_str()).unwrap();
        assert_eq!(id_from_key, id_from_string);
    }
});
