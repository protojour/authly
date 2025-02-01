use std::{borrow::Cow, time::Instant};

use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use hiqlite::Params;
use tracing::info;

use crate::{Db, DbError, FromRow, Row, LOG_QUERIES};

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

    async fn query_map<T>(&self, stmt: Cow<'static, str>, params: Params) -> Result<Vec<T>, DbError>
    where
        T: crate::FromRow + Send + 'static,
    {
        let values = hiqlite::Client::query_map::<HiqliteWrapper<T>, _>(self, stmt, params).await?;
        Ok(TransparentWrapperAlloc::<T>::peel_vec(values))
    }

    async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
        Ok(hiqlite::Client::execute(self, sql, params).await?)
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

/// Support transmute from HiqliteWrapper<T> to T
unsafe impl<T> TransparentWrapper<T> for HiqliteWrapper<T> {}
