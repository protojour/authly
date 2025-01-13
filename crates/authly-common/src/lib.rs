use std::{fmt::Display, marker::PhantomData, str::FromStr};

use serde::de::{Error, Visitor};

pub mod id;
pub mod property;
pub mod proto;
pub mod service;

#[cfg(feature = "access_token")]
pub mod access_token;

#[cfg(feature = "document")]
pub mod document;

pub mod policy;

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
