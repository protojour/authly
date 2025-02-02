//! sqlite integration with the `Db` trait
//!
//! This Db implementation is used in tests for now.

use core::str;

use hiqlite::Param;
use rusqlite::{
    params_from_iter,
    types::{ToSqlOutput, Value},
    ParamsFromIter,
};

use crate::Row;

pub struct RusqliteRowBorrowed<'a, 'b> {
    pub(super) row: &'a rusqlite::Row<'b>,
}

impl Row for RusqliteRowBorrowed<'_, '_> {
    fn get_int(&mut self, idx: &str) -> i64 {
        self.row.get(idx).unwrap()
    }

    fn get_opt_int(&mut self, idx: &str) -> Option<i64> {
        self.row.get(idx).unwrap()
    }

    fn get_text(&mut self, idx: &str) -> String {
        self.row.get(idx).unwrap()
    }

    fn get_opt_text(&mut self, idx: &str) -> Option<String> {
        self.row.get(idx).unwrap()
    }

    fn get_blob(&mut self, idx: &str) -> Vec<u8> {
        self.row.get(idx).unwrap()
    }

    fn get_blob_array<const N: usize>(&mut self, idx: &str) -> [u8; N] {
        self.row.get(idx).unwrap()
    }
}

pub(super) fn rusqlite_params(
    params: hiqlite::Params,
) -> ParamsFromIter<impl Iterator<Item = ToSqlOutput<'static>>> {
    params_from_iter(params.into_iter().map(|p| {
        ToSqlOutput::Owned(match p {
            Param::Null => Value::Null,
            Param::Integer(i) => Value::Integer(i),
            Param::Real(r) => Value::Real(r),
            Param::Text(t) => Value::Text(t),
            Param::Blob(vec) => Value::Blob(vec),
        })
    }))
}
