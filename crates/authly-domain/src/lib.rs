use std::{fmt::Display, marker::PhantomData, str::FromStr};

use rand::Rng;
use serde::{
    de::{Error, Visitor},
    Deserialize,
};

pub mod document;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EID(pub u128);

impl EID {
    pub fn random() -> Self {
        loop {
            let id: u128 = rand::thread_rng().gen();
            // low IDs are reserved for builtin/fixed
            if id > u16::MAX as u128 {
                return EID(id);
            }
        }
    }
}

#[repr(u32)]
pub enum BuiltinID {
    Authly = 0,
    PropEntity = 1,
    PropAuthlyRole = 2,
    AttrAuthlyRoleResolveSessionInfo = 3,
}

impl BuiltinID {
    pub fn to_eid(self) -> EID {
        EID(self as u128)
    }
}

#[derive(Debug)]
pub struct QualifiedAttributeName {
    pub property: String,
    pub attribute: String,
}

impl FromStr for EID {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = s.parse().map_err(|_| "invalid format")?;

        if id > 0 && id < 32768 {
            return Err("invalid value");
        }

        Ok(EID(id))
    }
}

impl<'de> Deserialize<'de> for EID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new("entity id"))
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
            phantom: PhantomData::default(),
        }
    }
}

impl<'de, T: FromStr> Visitor<'de> for FromStrVisitor<T>
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
