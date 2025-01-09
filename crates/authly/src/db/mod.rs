use std::{borrow::Cow, fmt::Display, future::Future};

use authly_domain::Eid;
use hiqlite::Params;
use thiserror::Error;

use crate::AuthlyCtx;

pub mod config_db;
pub mod document_db;
pub mod entity_db;
pub mod service_db;
pub mod session_db;
pub mod sqlite;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("db: {0}")]
    Hiqlite(hiqlite::Error),

    #[error("db: {0}")]
    Rusqlite(rusqlite::Error),

    #[error("timestamp encoding")]
    Timestamp,
}

impl From<hiqlite::Error> for DbError {
    fn from(value: hiqlite::Error) -> Self {
        Self::Hiqlite(value)
    }
}

pub type DbResult<T> = Result<T, DbError>;

/// Db abstraction around SQLite that works with both rusqlite and hiqlite
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

    fn txn<C, Q>(
        &self,
        sql: Q,
    ) -> impl Future<Output = Result<Vec<Result<usize, DbError>>, DbError>>
    where
        Q: IntoIterator<Item = (C, Params)>,
        C: Into<Cow<'static, str>>;
}

pub trait Row {
    fn get_int(&mut self, idx: &str) -> i64;

    #[expect(unused)]
    fn get_opt_int(&mut self, idx: &str) -> Option<i64>;

    fn get_text(&mut self, idx: &str) -> String;

    #[expect(unused)]
    fn get_opt_text(&mut self, idx: &str) -> Option<String>;

    fn get_blob(&mut self, idx: &str) -> Vec<u8>;
}

pub trait Convert: Sized {
    fn from_row(row: &mut impl Row, idx: &str) -> Self;

    fn as_param(&self) -> hiqlite::Param;
}

impl Convert for Eid {
    fn from_row(row: &mut impl Row, idx: &str) -> Self {
        let postcard: Vec<u8> = row.get_blob(idx);
        Self(postcard::from_bytes(&postcard).unwrap())
    }

    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(postcard::to_allocvec(&self.0).unwrap())
    }
}

pub trait Literal {
    type Lit: Display;

    fn literal(&self) -> Self::Lit;
}

impl Literal for Eid {
    type Lit = EIDLiteral;

    fn literal(&self) -> Self::Lit {
        EIDLiteral(postcard::to_allocvec(&self.0).unwrap())
    }
}

pub struct EIDLiteral(Vec<u8>);

impl Display for EIDLiteral {
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

impl<'a> Display for StrLiteral<'a> {
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

impl Db for AuthlyCtx {
    type Row<'a> = hiqlite::Row<'a>;

    async fn query_raw(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Self::Row<'_>>, DbError> {
        Ok(hiqlite::Client::query_raw(&self.db, stmt, params).await?)
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        Ok(hiqlite::Client::execute(&self.db, sql, params).await?)
    }

    async fn txn<C, Q>(&self, sql: Q) -> Result<Vec<Result<usize, DbError>>, DbError>
    where
        Q: IntoIterator<Item = (C, Params)>,
        C: Into<Cow<'static, str>>,
    {
        Ok(hiqlite::Client::txn(&self.db, sql)
            .await?
            .into_iter()
            .map(|res| res.map_err(DbError::Hiqlite))
            .collect())
    }
}

impl<'a> Row for hiqlite::Row<'a> {
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
