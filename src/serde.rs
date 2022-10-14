use crate::keys::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};
#[cfg(feature = "paserk")]
use crate::paserk::{FormatAsPaserk, Id};
use alloc::string::String;
use core::convert::TryFrom;

#[cfg(all(feature = "paserk", feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "paserk", feature = "serde"))))]
impl<V> serde::Serialize for AsymmetricPublicKey<V>
where
    AsymmetricPublicKey<V>: FormatAsPaserk,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let mut paserk_string = String::new();
        self.fmt(&mut paserk_string).map_err(S::Error::custom)?;
        serializer.serialize_str(&paserk_string)
    }
}

#[cfg(all(feature = "serde", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "serde", feature = "std"))))]
impl<'de, V> serde::Deserialize<'de> for AsymmetricPublicKey<V>
where
    AsymmetricPublicKey<V>: TryFrom<&'de str>,
    <AsymmetricPublicKey<V> as TryFrom<&'de str>>::Error: std::fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let paserk_string = <&str>::deserialize(deserializer)?;
        TryFrom::try_from(paserk_string).map_err(serde::de::Error::custom)
    }
}

#[cfg(all(feature = "paserk", feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "paserk", feature = "serde"))))]
impl<V> serde::Serialize for AsymmetricSecretKey<V>
where
    AsymmetricSecretKey<V>: FormatAsPaserk,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let mut paserk_string = String::new();
        self.fmt(&mut paserk_string).map_err(S::Error::custom)?;
        serializer.serialize_str(&paserk_string)
    }
}

#[cfg(all(feature = "serde", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "serde", feature = "std"))))]
impl<'de, V> serde::Deserialize<'de> for AsymmetricSecretKey<V>
where
    AsymmetricSecretKey<V>: TryFrom<&'de str>,
    <AsymmetricSecretKey<V> as TryFrom<&'de str>>::Error: std::fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let paserk_string = <&str>::deserialize(deserializer)?;
        TryFrom::try_from(paserk_string).map_err(serde::de::Error::custom)
    }
}

#[cfg(all(feature = "paserk", feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "paserk", feature = "serde"))))]
impl<V> serde::Serialize for SymmetricKey<V>
where
    SymmetricKey<V>: FormatAsPaserk,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let mut paserk_string = String::new();
        self.fmt(&mut paserk_string).map_err(S::Error::custom)?;
        serializer.serialize_str(&paserk_string)
    }
}

#[cfg(all(feature = "serde", feature = "std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "serde", feature = "std"))))]
impl<'de, V> serde::Deserialize<'de> for SymmetricKey<V>
where
    SymmetricKey<V>: TryFrom<&'de str>,
    <SymmetricKey<V> as TryFrom<&'de str>>::Error: std::fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let paserk_string = <&str>::deserialize(deserializer)?;
        TryFrom::try_from(paserk_string).map_err(serde::de::Error::custom)
    }
}

#[cfg(all(feature = "paserk", feature = "serde"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "paserk", feature = "serde"))))]
impl serde::Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let mut paserk_id = String::new();
        self.fmt(&mut paserk_id).map_err(S::Error::custom)?;
        serializer.serialize_str(&paserk_id)
    }
}

#[cfg(all(feature = "paserk", feature = "serde", feature = "std"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "paserk", feature = "serde", feature = "std")))
)]
impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let paserk_id = <&str>::deserialize(deserializer)?;
        TryFrom::try_from(paserk_id).map_err(serde::de::Error::custom)
    }
}
