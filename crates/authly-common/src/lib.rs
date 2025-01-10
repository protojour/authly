use std::{
    fmt::{Debug, Display},
    hash::Hash,
    io::Cursor,
    marker::PhantomData,
    str::FromStr,
};

use byteorder::{BigEndian, ReadBytesExt};
use rand::Rng;
use serde::{
    de::{Error, Visitor},
    Deserialize, Serialize,
};

#[cfg(feature = "access_token")]
pub mod access_token;

#[cfg(feature = "document")]
pub mod document;

/// Authly Identifier
pub struct Id128<K>(u128, PhantomData<K>);

impl<K> Id128<K> {
    pub const fn new(val: u128) -> Self {
        Self(val, PhantomData)
    }

    pub const fn value(&self) -> u128 {
        self.0
    }

    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(
            Cursor::new(bytes).read_u128::<BigEndian>().ok()?,
            PhantomData,
        ))
    }

    pub fn random() -> Self {
        loop {
            let id: u128 = rand::thread_rng().gen();
            // low IDs are reserved for builtin/fixed
            if id > u16::MAX as u128 {
                return Self(id, PhantomData);
            }
        }
    }
}

impl<K> Clone for Id128<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K> Copy for Id128<K> {}

impl<K> PartialEq for Id128<K> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<K> Eq for Id128<K> {}

impl<K> PartialOrd<Id128<K>> for Id128<K> {
    fn partial_cmp(&self, other: &Id128<K>) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl<K> Ord for Id128<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<K> Hash for Id128<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<K> Debug for Id128<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub mod idkind {
    pub trait IdKind {
        fn name() -> &'static str;
    }

    pub struct Entity;
    pub struct Object;

    impl IdKind for Entity {
        fn name() -> &'static str {
            "entity id"
        }
    }

    impl IdKind for Object {
        fn name() -> &'static str {
            "entity id"
        }
    }
}

/// Authly Entity ID
pub type Eid = Id128<idkind::Entity>;

pub type ObjId = Id128<idkind::Object>;

/// Authly Entity ID
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EidOld(pub u128);

impl EidOld {
    pub fn random() -> Self {
        loop {
            let id: u128 = rand::thread_rng().gen();
            // low IDs are reserved for builtin/fixed
            if id > u16::MAX as u128 {
                return EidOld(id);
            }
        }
    }

    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(Cursor::new(bytes).read_u128::<BigEndian>().ok()?))
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
    pub const fn to_obj_id(self) -> ObjId {
        Id128(self as u128, PhantomData)
    }

    pub const fn label(self) -> Option<&'static str> {
        match self {
            BuiltinID::Authly => None,
            BuiltinID::PropEntity => Some("entity"),
            BuiltinID::PropAuthlyRole => Some("authly:role"),
            BuiltinID::AttrAuthlyRoleGetAccessToken => Some("get_access_token"),
            BuiltinID::AttrAuthlyRoleAuthenticate => Some("authenticate"),
        }
    }

    pub const fn attributes(self) -> &'static [BuiltinID] {
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

impl FromStr for EidOld {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = s.parse().map_err(|_| "invalid format")?;

        if id > 0 && id < 32768 {
            return Err("invalid value");
        }

        Ok(EidOld(id))
    }
}

impl<K> FromStr for Id128<K> {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = s.parse().map_err(|_| "invalid format")?;

        if id > 0 && id < 32768 {
            return Err("invalid value");
        }

        Ok(Id128(id, PhantomData))
    }
}

impl<'de> Deserialize<'de> for EidOld {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new("entity id"))
    }
}

impl<'de, K: idkind::IdKind> Deserialize<'de> for Id128<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new(K::name()))
    }
}

impl Serialize for EidOld {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<K> Serialize for Id128<K> {
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
