//! service utilities

use std::collections::HashMap;

use fnv::FnvHashSet;

use crate::id::ObjId;

#[derive(Default)]
pub struct PropertyMapping {
    pub properties: HashMap<String, AttributeMappings>,
}

#[derive(Default)]
pub struct AttributeMappings {
    pub attributes: HashMap<String, ObjId>,
}

impl PropertyMapping {
    pub fn translate<'a>(
        &self,
        attributes: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> FnvHashSet<u128> {
        let mut output = FnvHashSet::default();
        for (prop, attr) in attributes {
            let Some(attr_mappings) = self.properties.get(prop) else {
                continue;
            };
            let Some(attr_id) = attr_mappings.attributes.get(attr) else {
                continue;
            };

            output.insert(attr_id.value());
        }

        output
    }
}
