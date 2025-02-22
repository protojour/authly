//! sqlite integration with the `Db` trait
//!
//! This Db implementation is used in tests for now.

use core::str;

use rusqlite::{params_from_iter, types::ToSqlOutput, ParamsFromIter};

use crate::Row;

#[derive(Clone)]
pub enum RusqliteParam {
    Value(rusqlite::types::Value),
    StmtOutputIndexed(usize, usize),
}

impl From<i64> for RusqliteParam {
    fn from(value: i64) -> Self {
        Self::Value(value.into())
    }
}

impl From<Option<i64>> for RusqliteParam {
    fn from(value: Option<i64>) -> Self {
        Self::Value(value.into())
    }
}

impl From<String> for RusqliteParam {
    fn from(value: String) -> Self {
        Self::Value(value.into())
    }
}

impl From<Option<String>> for RusqliteParam {
    fn from(value: Option<String>) -> Self {
        Self::Value(value.into())
    }
}

impl From<Vec<u8>> for RusqliteParam {
    fn from(value: Vec<u8>) -> Self {
        Self::Value(value.into())
    }
}

impl From<&str> for RusqliteParam {
    fn from(value: &str) -> Self {
        Self::Value(value.to_string().into())
    }
}

impl From<Option<&str>> for RusqliteParam {
    fn from(value: Option<&str>) -> Self {
        Self::Value(value.map(|s| s.to_string()).into())
    }
}

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
    params: Vec<RusqliteParam>,
) -> ParamsFromIter<impl Iterator<Item = ToSqlOutput<'static>>> {
    params_from_iter(params.into_iter().map(|p| {
        ToSqlOutput::Owned(match p {
            RusqliteParam::Value(value) => value,
            _ => panic!("variables only work in transaction context"),
        })
    }))
}
