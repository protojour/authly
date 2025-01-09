use std::{fmt::Display, marker::PhantomData, str::FromStr};

use rand::Rng;
use serde::{
    de::{Error, Visitor},
    Deserialize, Serialize,
};

#[cfg(feature = "access_token")]
pub mod access_token;

#[cfg(feature = "document")]
pub mod document;

/// Authly Entity ID
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Eid(pub u128);

impl Eid {
    pub fn random() -> Self {
        loop {
            let id: u128 = rand::thread_rng().gen();
            // low IDs are reserved for builtin/fixed
            if id > u16::MAX as u128 {
                return Eid(id);
            }
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum BuiltinID {
    Authly = 0,
    PropEntity = 1,
    PropAuthlyRole = 2,
    AttrAuthlyRoleGetAccessToken = 3,
    AttrAuthlyRoleAuthenticate = 4,
}

impl BuiltinID {
    pub fn to_eid(self) -> Eid {
        Eid(self as u128)
    }

    pub fn label(self) -> Option<&'static str> {
        match self {
            BuiltinID::Authly => None,
            BuiltinID::PropEntity => Some("entity"),
            BuiltinID::PropAuthlyRole => Some("authly:role"),
            BuiltinID::AttrAuthlyRoleGetAccessToken => Some("get_access_token"),
            BuiltinID::AttrAuthlyRoleAuthenticate => Some("authenticate"),
        }
    }

    pub fn attributes(self) -> &'static [BuiltinID] {
        match self {
            Self::PropAuthlyRole => &[
                Self::AttrAuthlyRoleGetAccessToken,
                Self::AttrAuthlyRoleAuthenticate,
            ],
            _ => &[],
        }
    }
}

#[derive(Debug)]
pub struct QualifiedAttributeName {
    pub property: String,
    pub attribute: String,
}

impl FromStr for Eid {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = s.parse().map_err(|_| "invalid format")?;

        if id > 0 && id < 32768 {
            return Err("invalid value");
        }

        Ok(Eid(id))
    }
}

impl<'de> Deserialize<'de> for Eid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new("entity id"))
    }
}

impl Serialize for Eid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl FromStr for QualifiedAttributeName {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut segments = s.split("/");
        let property = segments.next().ok_or("missing property name")?;
        let attribute = segments.next().ok_or("missing attribute name")?;

        Ok(Self {
            property: property.to_string(),
            attribute: attribute.to_string(),
        })
    }
}

impl<'de> Deserialize<'de> for QualifiedAttributeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new("attribute name"))
    }
}

#[derive(Default)]
struct FromStrVisitor<T> {
    expecting: &'static str,
    phantom: PhantomData<T>,
}

impl<T> FromStrVisitor<T> {
    pub fn new(expecting: &'static str) -> Self {
        Self {
            expecting,
            phantom: PhantomData,
        }
    }
}

impl<T: FromStr> Visitor<'_> for FromStrVisitor<T>
where
    T::Err: Display,
{
    type Value = T;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.expecting)
    }

    fn visit_str<E: Error>(self, str: &str) -> Result<Self::Value, E> {
        T::from_str(str).map_err(|msg| E::custom(msg))
    }
}
