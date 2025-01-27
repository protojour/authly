use authly_common::id::Id128;

pub trait AsParam: Sized {
    fn as_param(&self) -> hiqlite::Param;
}

impl<K> AsParam for Id128<K> {
    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(self.to_bytes().to_vec())
    }
}
