use std::{borrow::Cow, future::Future, marker::PhantomData};

use authly_common::id::Id128;
use hiqlite::Params;
use itertools::Itertools;
use thiserror::Error;

pub mod literal;
pub mod param;
pub mod sqlite_pool;

mod hql;
mod sqlite;

const LOG_QUERIES: bool = false;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("db: {0}")]
    Hiqlite(hiqlite::Error),

    #[error("db: {0}")]
    Rusqlite(rusqlite::Error),

    #[error("channel error")]
    Channel,

    #[error("timestamp encoding")]
    Timestamp,

    #[error("binary encoding")]
    BinaryEncoding,
}

impl From<hiqlite::Error> for DbError {
    fn from(value: hiqlite::Error) -> Self {
        Self::Hiqlite(value)
    }
}

pub type DbResult<T> = Result<T, DbError>;

/// Db abstraction around SQLite that works with both rusqlite and hiqlite.
pub trait Db: Send + Sync + 'static {
    type Row<'a>: Row
    where
        Self: 'a;

    fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<Vec<Self::Row<'_>>, DbError>> + Send;

    fn query_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<Vec<T>, DbError>> + Send
    where
        T: FromRow + Send + 'static;

    fn execute(
        &self,
        sql: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<usize, DbError>> + Send;

    /// Execute multiple statements in a transaction
    fn transact(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> impl Future<Output = Result<Vec<Result<usize, DbError>>, DbError>> + Send;
}

pub trait Row {
    #[track_caller]
    fn get_int(&mut self, idx: &str) -> i64;

    #[track_caller]
    fn get_opt_int(&mut self, idx: &str) -> Option<i64>;

    #[track_caller]
    fn get_text(&mut self, idx: &str) -> String;

    #[track_caller]
    fn get_opt_text(&mut self, idx: &str) -> Option<String>;

    #[track_caller]
    fn get_blob(&mut self, idx: &str) -> Vec<u8>;

    #[track_caller]
    fn get_blob_array<const N: usize>(&mut self, idx: &str) -> [u8; N];

    #[track_caller]
    fn get_datetime(&mut self, idx: &str) -> DbResult<time::OffsetDateTime> {
        time::OffsetDateTime::from_unix_timestamp(self.get_int(idx)).map_err(|_| DbError::Timestamp)
    }

    #[track_caller]
    fn get_id<K>(&mut self, idx: &str) -> Id128<K> {
        Id128::from_array(&self.get_blob_array(idx))
    }

    /// Read Ids that have been produced with sqlite `group_concat` producing a concatenated BLOB
    #[track_caller]
    fn get_ids_concatenated<K>(&mut self, idx: &str) -> IdsConcatenated<K> {
        IdsConcatenated {
            iter: self.get_blob(idx).into_iter(),
            _phantom: PhantomData,
        }
    }
}

pub struct IdsConcatenated<K> {
    iter: std::vec::IntoIter<u8>,
    _phantom: PhantomData<K>,
}

impl<K> Iterator for IdsConcatenated<K> {
    type Item = Id128<K>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(Id128::from_array(&self.iter.next_array()?))
    }
}

pub trait FromRow {
    fn from_row(row: &mut impl Row) -> Self;
}
