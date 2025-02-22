use authly_db::{FromRow, Row};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DirKey(pub i64);

impl FromRow for DirKey {
    fn from_row(row: &mut impl Row) -> Self {
        Self(row.get_int("key"))
    }
}

pub struct DirForeignKey(pub DirKey);

impl FromRow for DirForeignKey {
    fn from_row(row: &mut impl Row) -> Self {
        Self(DirKey(row.get_int("dir_key")))
    }
}
