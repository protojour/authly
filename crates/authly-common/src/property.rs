use std::str::FromStr;

use serde::Deserialize;

use crate::FromStrVisitor;

#[derive(Debug)]
pub struct QualifiedAttributeName {
    pub property: String,
    pub attribute: String,
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
