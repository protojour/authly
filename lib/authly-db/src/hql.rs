use std::{borrow::Cow, time::Instant};

use hiqlite::Params;
use tracing::info;

use crate::{Db, DbError, Row, LOG_QUERIES};

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
