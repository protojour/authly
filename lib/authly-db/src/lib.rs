use std::{borrow::Cow, future::Future};

use authly_common::id::Id128;
use hiqlite::Params;
use thiserror::Error;

pub mod literal;
pub mod param;

mod hql;
mod sqlite;

const LOG_QUERIES: bool = false;

#[derive(Clone, Copy)]
pub struct IsLeaderDb(pub bool);

#[derive(Error, Debug)]
pub enum DbError {
    #[error("db: {0}")]
    Hiqlite(hiqlite::Error),

    #[error("db: {0}")]
    Rusqlite(rusqlite::Error),

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
///
/// Does not support transactions, so transactions must be tested agains the various concrete connection types.
pub trait Db {
    type Row<'a>: Row
    where
        Self: 'a;

    fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<Vec<Self::Row<'_>>, DbError>>;

    fn execute(
        &self,
        sql: Cow<'static, str>,
        params: Params,
    ) -> impl Future<Output = Result<usize, DbError>>;

    /// Execute multiple statements in a transaction
    fn txn(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> impl Future<Output = Result<Vec<Result<usize, DbError>>, DbError>>;
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

/// Trait for getting the "database".
///
/// This trait can be used with in "entrait-pattern" style dependency injection.
pub trait GetDb {
    type Db: Db;

    fn get_db(&self) -> &Self::Db;
}

/// Every GetDb is also a Db:
impl<T: GetDb + 'static> Db for T {
    type Row<'a> = <<T as GetDb>::Db as Db>::Row<'a>;

    async fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Self::Row<'_>>, DbError> {
        Db::query_raw(self.get_db(), stmt, params).await
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        Db::execute(self.get_db(), sql, params).await
    }

    async fn txn(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> Result<Vec<Result<usize, DbError>>, DbError> {
        Db::txn(self.get_db(), sql).await
    }
}
