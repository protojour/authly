use std::{borrow::Cow, fmt::Debug};

use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use hiqlite::Params;

use crate::{Db, DbError, FromRow, Row, TryFromRow};

impl Db for hiqlite::Client {
    async fn query_map<T>(&self, stmt: Cow<'static, str>, params: Params) -> Result<Vec<T>, DbError>
    where
        T: crate::FromRow + Send + 'static,
    {
        let values = hiqlite::Client::query_map::<HiqliteWrapper<T>, _>(self, stmt, params).await?;
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
                .await?
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
            hiqlite::Client::query_map_optional::<HiqliteWrapper<Result<T, T::Error>>, _>(
                self, stmt, params,
            )
            .await?
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
        let values = hiqlite::Client::query_map::<HiqliteWrapper<Result<T, T::Error>>, _>(
            self, stmt, params,
        )
        .await?;
        Ok(values
            .into_iter()
            .filter_map(|HiqliteWrapper(result)| match result {
                Ok(result) => Some(result),
                Err(err) => {
                    tracing::error!(?err, "row error");
                    None
                }
            })
            .collect())
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        Ok(hiqlite::Client::execute(self, sql, params).await?)
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
                .await?;
        Ok(values
            .into_iter()
            .map(|result| result.map(|wrapper| wrapper.0).map_err(|err| err.into()))
            .collect())
    }

    async fn transact(
        &self,
        sql: Vec<(Cow<'static, str>, Params)>,
    ) -> Result<Vec<Result<usize, DbError>>, DbError> {
        Ok(hiqlite::Client::txn(self, sql)
            .await?
            .into_iter()
            .map(|result| result.map_err(|err| err.into()))
            .collect())
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

    fn get_blob_array<const N: usize>(&mut self, idx: &str) -> [u8; N] {
        self.get(idx)
    }
}

#[repr(transparent)]
struct HiqliteWrapper<T>(T);

impl<T: FromRow> From<hiqlite::Row<'_>> for HiqliteWrapper<T> {
    fn from(mut row: hiqlite::Row) -> Self {
        Self(T::from_row(&mut row))
    }
}

impl<T: TryFromRow> From<hiqlite::Row<'_>> for HiqliteWrapper<Result<T, T::Error>> {
    fn from(mut row: hiqlite::Row) -> Self {
        Self(T::try_from_row(&mut row))
    }
}

/// Support transmute from HiqliteWrapper<T> to T
unsafe impl<T> TransparentWrapper<T> for HiqliteWrapper<T> {}
