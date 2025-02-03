use std::{borrow::Cow, fmt::Debug, future::Future, marker::PhantomData};

use authly_common::id::Id128DynamicArrayConv;
use hiqlite::Params;
use itertools::Itertools;
use thiserror::Error;

pub mod literal;
pub mod param;
pub mod sqlite_pool;

mod hql;
mod sqlite;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("db: {0}")]
    Hiqlite(hiqlite::Error),

    #[error("db: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error("too many rows")]
    TooManyRows,

    #[error("connection pool error: {0}")]
    Pool(String),

    #[error("join error")]
    Join(#[from] tokio::task::JoinError),

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
    /// Query for a Vec of values implementing [FromRow].
    fn query_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<Vec<T>, DbError>> + Send
    where
        T: FromRow + Send + 'static;

    /// Query either zero or one row
    fn query_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<Option<T>, DbError>> + Send
    where
        T: FromRow + Send + 'static;

    /// Query either zero or one row, with fallible deserialization
    fn query_try_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<Option<Result<T, T::Error>>, DbError>> + Send
    where
        T: TryFromRow + Send + 'static;

    /// Query Vec of type implementing [TryFromRow], tracing the error rows before filtering them out.
    fn query_filter_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<Vec<T>, DbError>> + Send
    where
        T: TryFromRow + Send + 'static,
        <T as TryFromRow>::Error: Debug;

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
    fn get_id<T: Id128DynamicArrayConv>(&mut self, idx: &str) -> T {
        T::try_from_array_dynamic(&self.get_blob_array(idx)).unwrap()
    }

    /// Read Ids that have been produced with sqlite `group_concat` producing a concatenated BLOB
    #[track_caller]
    fn get_ids_concatenated<T>(&mut self, idx: &str) -> IdsConcatenated<T> {
        IdsConcatenated {
            iter: self.get_blob(idx).into_iter(),
            _phantom: PhantomData,
        }
    }
}

pub struct IdsConcatenated<T> {
    iter: std::vec::IntoIter<u8>,
    _phantom: PhantomData<T>,
}

impl<T: Id128DynamicArrayConv> Iterator for IdsConcatenated<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        T::try_from_array_dynamic(&self.iter.next_array()?)
    }
}

pub trait FromRow {
    fn from_row(row: &mut impl Row) -> Self;
}

pub trait TryFromRow: Sized {
    type Error: Send + 'static;

    fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error>;
}
