use std::{borrow::Cow, fmt::Debug, ops::Deref};

use authly_db::{Db, DbError, FromRow, Row, TryFromRow};
use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use hiqlite::{Params, StmtIndex};

#[derive(Clone)]
pub struct HiqliteClient {
    client: hiqlite::Client,
}

impl HiqliteClient {
    pub const fn new(client: hiqlite::Client) -> Self {
        Self { client }
    }
}

impl Deref for HiqliteClient {
    type Target = hiqlite::Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl Db for HiqliteClient {
    type Param = hiqlite::Param;

    async fn query_map<T>(&self, stmt: Cow<'static, str>, params: Params) -> Result<Vec<T>, DbError>
    where
        T: crate::FromRow + Send + 'static,
    {
        let values = hiqlite::Client::query_map::<HiqliteWrapper<T>, _>(self, stmt, params)
            .await
            .map_err(hql_err)?;
        Ok(TransparentWrapperAlloc::<T>::peel_vec(values))
    }

    async fn query_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Option<T>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        Ok(
            hiqlite::Client::query_map_optional::<HiqliteWrapper<T>, _>(self, stmt, params)
                .await
                .map_err(hql_err)?
                .map(|wrapper| wrapper.0),
        )
    }

    async fn query_try_map_opt<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Option<Result<T, T::Error>>, DbError>
    where
        T: TryFromRow + Send + 'static,
    {
        Ok(
            hiqlite::Client::query_map_optional::<HiqliteTryWrapper<Result<T, T::Error>>, _>(
                self, stmt, params,
            )
            .await
            .map_err(hql_err)?
            .map(|wrapper| wrapper.0),
        )
    }

    async fn query_filter_map<T>(
        &self,
        stmt: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<T>, DbError>
    where
        T: crate::TryFromRow + Send + 'static,
        <T as TryFromRow>::Error: Debug,
    {
        let values = hiqlite::Client::query_map::<HiqliteTryWrapper<Result<T, T::Error>>, _>(
            self, stmt, params,
        )
        .await
        .map_err(hql_err)?;
        Ok(values
            .into_iter()
            .filter_map(|HiqliteTryWrapper(result)| match result {
                Ok(result) => Some(result),
                Err(err) => {
                    tracing::error!(?err, "row error");
                    None
                }
            })
            .collect())
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        hiqlite::Client::execute(self, sql, params)
            .await
            .map_err(hql_err)
    }

    async fn execute_map<T>(
        &self,
        sql: Cow<'static, str>,
        params: Params,
    ) -> Result<Vec<Result<T, DbError>>, DbError>
    where
        T: FromRow + Send + 'static,
    {
        let values =
            hiqlite::Client::execute_returning_map::<_, HiqliteWrapper<T>>(self, sql, params)
                .await
                .map_err(hql_err)?;
        Ok(values
            .into_iter()
            .map(|result| result.map(|wrapper| wrapper.0).map_err(hql_err))
            .collect())
    }

    fn stmt_column(stmt_index: usize, column_index: usize) -> Self::Param {
        StmtIndex(stmt_index).column(column_index).into()
    }

    async fn transact(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> Result<Vec<Result<usize, DbError>>, DbError> {
        Ok(hiqlite::Client::txn(self, sql)
            .await
            .map_err(hql_err)?
            .into_iter()
            .map(|result| result.map_err(hql_err))
            .collect())
    }
}

pub struct HqlRow<'a>(hiqlite::Row<'a>);

impl Row for HqlRow<'_> {
    fn get_int(&mut self, idx: &str) -> i64 {
        self.0.get(idx)
    }

    fn get_opt_int(&mut self, idx: &str) -> Option<i64> {
        self.0.get(idx)
    }

    fn get_text(&mut self, idx: &str) -> String {
        self.0.get(idx)
    }

    fn get_opt_text(&mut self, idx: &str) -> Option<String> {
        self.0.get(idx)
    }

    fn get_blob(&mut self, idx: &str) -> Vec<u8> {
        self.0.get(idx)
    }

    fn get_blob_array<const N: usize>(&mut self, idx: &str) -> [u8; N] {
        self.0.get(idx)
    }
}

#[repr(transparent)]
struct HiqliteWrapper<T>(T);

impl<T: FromRow> From<hiqlite::Row<'_>> for HiqliteWrapper<T> {
    fn from(row: hiqlite::Row) -> Self {
        Self(T::from_row(&mut HqlRow(row)))
    }
}

#[repr(transparent)]
struct HiqliteTryWrapper<T>(T);

impl<T: TryFromRow> From<hiqlite::Row<'_>> for HiqliteTryWrapper<Result<T, T::Error>> {
    fn from(row: hiqlite::Row) -> Self {
        Self(T::try_from_row(&mut HqlRow(row)))
    }
}

/// Support transmute from HiqliteWrapper<T> to T
unsafe impl<T> TransparentWrapper<T> for HiqliteWrapper<T> {}
unsafe impl<T> TransparentWrapper<T> for HiqliteTryWrapper<T> {}

fn hql_err(err: hiqlite::Error) -> DbError {
    match err {
        hiqlite::Error::Sqlite(msg) => DbError::Sqlite(msg),
        err => DbError::Other(format!("{err:?}").into()),
    }
}
