use std::fmt::{self, Display};

use base64::{prelude::BASE64_URL_SAFE, Engine};
use hex::{FromHex, ToHex};
use serde::{de::Visitor, Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Hex<T: FromHex<Error: Display> + ToHex + AsRef<[u8]> = Vec<u8>>(
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    pub T,
);

#[derive(Clone)]
pub struct UrlSafeBase64(pub Vec<u8>);

impl Serialize for UrlSafeBase64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let b64 = BASE64_URL_SAFE.encode(&self.0);
        serializer.serialize_str(&b64)
    }
}

impl<'de> Deserialize<'de> for UrlSafeBase64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visit;

        impl Visitor<'_> for Visit {
            type Value = UrlSafeBase64;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a Base64 encoded string")
            }

            fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                BASE64_URL_SAFE
                    .decode(data)
                    .map(UrlSafeBase64)
                    .map_err(|_e| serde::de::Error::custom("bad encoding"))
            }
        }

        deserializer.deserialize_str(Visit)
    }
}
