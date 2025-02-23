use core::str;

use rusqlite::{params_from_iter, types::ToSqlOutput, ParamsFromIter};

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
