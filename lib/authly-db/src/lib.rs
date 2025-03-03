use std::{borrow::Cow, fmt::Debug, future::Future, marker::PhantomData};

use authly_common::id::Id128DynamicArrayConv;
use itertools::Itertools;
use thiserror::Error;

pub mod literal;
pub mod param;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("sql: {0}")]
    Sql(Cow<'static, str>),

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

    #[error("other")]
    Other(Cow<'static, str>),
}

pub type DbResult<T> = Result<T, DbError>;

/// Can be used to represent whether an UPSERT did insert or update
pub struct DidInsert(pub bool);

/// Db abstraction around SQLite that works with any SQLite "flavour" (including hiqlite).
pub trait Db: Send + Sync + 'static {
    type Param: Clone
        + From<i64>
        + From<Option<i64>>
        + From<String>
        + From<Option<String>>
        + From<Vec<u8>>
        + for<'a> From<&'a str>
        + for<'a> From<Option<&'a str>>;

    /// Query for a Vec of values implementing [FromRow].
    fn query_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Vec<Self::Param>,
    ) -> impl Future<Output = Result<Vec<T>, DbError>> + Send
    where
        T: FromRow + Send + 'static;

    /// Query either zero or one row
    fn query_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Vec<Self::Param>,
    ) -> impl Future<Output = Result<Option<T>, DbError>> + Send
    where
        T: FromRow + Send + 'static;

    /// Query either zero or one row, with fallible deserialization
    fn query_try_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Vec<Self::Param>,
    ) -> impl Future<Output = Result<Option<Result<T, T::Error>>, DbError>> + Send
    where
        T: TryFromRow + Send + 'static;

    /// Query Vec of type implementing [TryFromRow], tracing the error rows before filtering them out.
    fn query_filter_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Vec<Self::Param>,
    ) -> impl Future<Output = Result<Vec<T>, DbError>> + Send
    where
        T: TryFromRow + Send + 'static,
        <T as TryFromRow>::Error: Debug;

    fn execute(
        &self,
        sql: Cow<'static, str>,
        params: Vec<Self::Param>,
    ) -> impl Future<Output = Result<usize, DbError>> + Send;

    fn execute_map<T>(
        &self,
        sql: Cow<'static, str>,
        params: Vec<Self::Param>,
    ) -> impl Future<Output = Result<Vec<Result<T, DbError>>, DbError>> + Send
    where
        T: FromRow + Send + 'static;

    /// Refer to a statement+column index, which is valid inside a transaction.
    fn stmt_column(stmt_index: usize, column_index: usize) -> Self::Param;

    /// Execute multiple statements in a transaction
    fn transact(
        &self,
        sql: Vec<(Cow<'static, str>, Vec<Self::Param>)>,
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
    fn get_opt_datetime(&mut self, idx: &str) -> DbResult<Option<time::OffsetDateTime>> {
        match self.get_opt_int(idx) {
            Some(timestamp) => time::OffsetDateTime::from_unix_timestamp(timestamp)
                .map(Some)
                .map_err(|_| DbError::Timestamp),
            None => Ok(None),
        }
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

pub type Params<D> = Vec<<D as Db>::Param>;

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

#[macro_export]
macro_rules! params {
    ( $( $param:expr ),* ) => {
        {
            #[allow(unused_mut)]
            let mut params = Vec::with_capacity(2);
            $(
                params.push($param.into());
            )*
            params
        }
    };
}
