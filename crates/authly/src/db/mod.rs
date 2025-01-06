use authly_domain::EID;
use hiqlite::Row;

pub mod config_db;
pub mod document_db;
pub mod entity_db;
pub mod service_db;

pub trait Convert: Sized {
    fn from_row(row: &mut Row, idx: &str) -> Self;

    fn as_param(&self) -> hiqlite::Param;
}

impl Convert for EID {
    fn from_row(row: &mut Row, idx: &str) -> Self {
        let postcard: Vec<u8> = row.get(idx);
        Self(postcard::from_bytes(&postcard).unwrap())
    }

    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(postcard::to_allocvec(&self.0).unwrap())
    }
}
