use std::{borrow::Cow, fmt::Display, future::Future, time::Instant};

use authly_common::id::Id128;
use hiqlite::Params;
use thiserror::Error;
use tracing::info;

use crate::AuthlyCtx;

pub mod config_db;
pub mod document_db;
pub mod entity_db;
pub mod service_db;
pub mod session_db;
pub mod settings_db;
pub mod sqlite;

const LOG_QUERIES: bool = false;

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
}

pub trait Row {
    fn get_int(&mut self, idx: &str) -> i64;

    fn get_opt_int(&mut self, idx: &str) -> Option<i64>;

    fn get_text(&mut self, idx: &str) -> String;

    fn get_opt_text(&mut self, idx: &str) -> Option<String>;

    fn get_blob(&mut self, idx: &str) -> Vec<u8>;
}

pub trait Convert: Sized {
    fn from_row(row: &mut impl Row, idx: &str) -> Self;

    fn as_param(&self) -> hiqlite::Param;
}

impl<K> Convert for Id128<K> {
    fn from_row(row: &mut impl Row, idx: &str) -> Self {
        Self::from_bytes(&row.get_blob(idx)).unwrap()
    }

    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(self.to_bytes().to_vec())
    }
}

pub trait Literal {
    type Lit: Display;

    fn literal(&self) -> Self::Lit;
}

impl<K> Literal for Id128<K> {
    type Lit = IdLiteral;

    fn literal(&self) -> Self::Lit {
        IdLiteral(self.to_bytes())
    }
}

pub struct IdLiteral([u8; 16]);

impl Display for IdLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "x'{}'", hexhex::hex(&self.0))
    }
}

impl<'a> Literal for &'a str {
    type Lit = StrLiteral<'a>;

    fn literal(&self) -> Self::Lit {
        StrLiteral(self)
    }
}

pub struct StrLiteral<'a>(&'a str);

impl Display for StrLiteral<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'")?;

        for char in self.0.chars() {
            if char == '\'' {
                write!(f, "''")?;
            } else {
                write!(f, "{char}")?;
            }
        }

        write!(f, "'")?;

        Ok(())
    }
}

impl Db for hiqlite::Client {
    type Row<'a> = hiqlite::Row<'a>;

    #[tracing::instrument(skip(self, params))]
    async fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Self::Row<'_>>, DbError> {
        if LOG_QUERIES {
            let start = Instant::now();
            let result = hiqlite::Client::query_raw(self, stmt, params).await;
            info!("query_raw took {:?}", start.elapsed());
            Ok(result?)
        } else {
            Ok(hiqlite::Client::query_raw(self, stmt, params).await?)
        }
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        Ok(hiqlite::Client::execute(self, sql, params).await?)
    }
}

impl Db for AuthlyCtx {
    type Row<'a> = hiqlite::Row<'a>;

    async fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Self::Row<'_>>, DbError> {
        Db::query_raw(&self.hql, stmt, params).await
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        Db::execute(&self.hql, sql, params).await
    }
}

impl Row for hiqlite::Row<'_> {
    fn get_int(&mut self, idx: &str) -> i64 {
        self.get(idx)
    }

    fn get_opt_int(&mut self, idx: &str) -> Option<i64> {
        self.get(idx)
    }

    fn get_text(&mut self, idx: &str) -> String {
        self.get(idx)
    }

    fn get_opt_text(&mut self, idx: &str) -> Option<String> {
        self.get(idx)
    }

    fn get_blob(&mut self, idx: &str) -> Vec<u8> {
        self.get(idx)
    }
}
