use fnv::FnvHashMap;

use crate::{
    directory::DirKey,
    id::{BuiltinAttr, BuiltinProp},
};

pub struct Builtins {
    pub authly_dir_key: DirKey,
    pub authly_namespace_key: i64,

    pub prop_keys: FnvHashMap<BuiltinProp, i64>,
    pub attr_keys: FnvHashMap<BuiltinAttr, i64>,
}

impl Builtins {
    pub fn prop_key(&self, prop: BuiltinProp) -> i64 {
        self.prop_keys
            .get(&prop)
            .copied()
            .expect("builtin prop without key")
    }

    pub fn attr_key(&self, attr: BuiltinAttr) -> i64 {
        self.attr_keys
            .get(&attr)
            .copied()
            .expect("builtin attr without key")
    }
}
