use authly_common::id::{
    kind::IdKind, subset::IdKindSubset, DynamicId, Id128, Id128DynamicArrayConv,
};

pub trait ToBlob {
    fn to_blob(&self) -> Vec<u8>;
}

impl ToBlob for &[u8] {
    fn to_blob(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl<K: IdKind> ToBlob for Id128<K> {
    fn to_blob(&self) -> Vec<u8> {
        self.to_array_dynamic().to_vec()
    }
}

impl<KS: IdKindSubset> ToBlob for DynamicId<KS> {
    fn to_blob(&self) -> Vec<u8> {
        self.to_array_dynamic().to_vec()
    }
}
