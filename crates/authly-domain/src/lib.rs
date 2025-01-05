use std::str::FromStr;

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
            if id > 32767 {
                return EID(id);
            }
        }
    }
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
        struct EIDVisitor;

        impl<'de> Visitor<'de> for EIDVisitor {
            type Value = EID;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "entity id")
            }

            fn visit_str<E: Error>(self, str: &str) -> Result<Self::Value, E> {
                EID::from_str(str).map_err(|msg| E::custom(msg))
            }
        }

        deserializer.deserialize_str(EIDVisitor)
    }
}
