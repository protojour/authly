use std::{borrow::Cow, future::Future};

use authly_common::id::Id128;
use hiqlite::Params;
use thiserror::Error;

pub mod literal;
pub mod param;
pub mod sqlite_handle;

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
    fn get_int(&mut self, idx: &str) -> i64;

    fn get_opt_int(&mut self, idx: &str) -> Option<i64>;

    fn get_text(&mut self, idx: &str) -> String;

    fn get_opt_text(&mut self, idx: &str) -> Option<String>;

    fn get_blob(&mut self, idx: &str) -> Vec<u8>;

    fn get_datetime(&mut self, idx: &str) -> DbResult<time::OffsetDateTime> {
        time::OffsetDateTime::from_unix_timestamp(self.get_int(idx)).map_err(|_| DbError::Timestamp)
    }

    fn get_id<K>(&mut self, idx: &str) -> Id128<K> {
        Id128::from_bytes(&self.get_blob(idx)).unwrap()
    }
}
