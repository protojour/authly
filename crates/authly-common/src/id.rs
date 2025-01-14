use std::{fmt::Debug, hash::Hash, io::Cursor, marker::PhantomData, str::FromStr};

use byteorder::{BigEndian, ReadBytesExt};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::FromStrVisitor;

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

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum BuiltinID {
    /// Id representing Authly itself
    Authly = 0,
    /// The entity property
    PropEntity = 1,
    /// The built-in authly:role for authly internal access control
    PropAuthlyRole = 2,
    /// A service role for getting an access token
    AttrAuthlyRoleGetAccessToken = 3,
    /// A service role for authenticating users
    AttrAuthlyRoleAuthenticate = 4,
    /// A user role for applying documents
    AttrAuthlyRoleApplyDocument = 5,
    /// The entity membership relation
    RelEntityMembership = 6,
    /// The username ident property
    PropUsername = 7,
    /// The email ident property
    PropEmail = 8,
    /// The password_hash text property
    PropPasswordHash = 9,
    /// The label text property
    PropLabel = 10,
    /// The kubernetes service account name property.
    /// The value format is `{namespace}/{account_name}`.
    PropK8sServiceAccount = 11,
}

impl BuiltinID {
    pub const fn to_obj_id(self) -> ObjId {
        Id128(self as u128, PhantomData)
    }

    pub const fn label(self) -> Option<&'static str> {
        match self {
            Self::Authly => None,
            Self::PropEntity => Some("entity"),
            Self::PropAuthlyRole => Some("authly:role"),
            Self::AttrAuthlyRoleGetAccessToken => Some("get_access_token"),
            Self::AttrAuthlyRoleAuthenticate => Some("authenticate"),
            Self::AttrAuthlyRoleApplyDocument => Some("apply_document"),
            Self::PropUsername => None,
            Self::PropEmail => None,
            Self::RelEntityMembership => None,
            Self::PropPasswordHash => None,
            Self::PropLabel => None,
            Self::PropK8sServiceAccount => None,
        }
    }

    pub const fn attributes(self) -> &'static [BuiltinID] {
        match self {
            Self::PropAuthlyRole => &[
                Self::AttrAuthlyRoleGetAccessToken,
                Self::AttrAuthlyRoleAuthenticate,
                Self::AttrAuthlyRoleApplyDocument,
            ],
            _ => &[],
        }
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

impl<'de, K: idkind::IdKind> Deserialize<'de> for Id128<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new(K::name()))
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
