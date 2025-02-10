use authly_common::id::{
    kind::IdKind, subset::IdKindSubset, DynamicId, Id128, Id128DynamicArrayConv,
};

pub trait AsParam: Sized {
    fn as_param(&self) -> hiqlite::Param;
}

impl<K: IdKind> AsParam for Id128<K> {
    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(self.to_array_dynamic().to_vec())
    }
}

impl<KS: IdKindSubset> AsParam for DynamicId<KS> {
    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(self.to_array_dynamic().to_vec())
    }
}
