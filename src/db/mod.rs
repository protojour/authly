use std::borrow::Cow;

use authly_db::{Db, DbError};
use hiqlite::Params;

use crate::{ctx::GetDb, AuthlyCtx};

pub mod authority_mandate_db;
pub mod cryptography_db;
pub mod document_db;
pub mod entity_db;
pub mod service_db;
pub mod session_db;
pub mod settings_db;

impl Db for AuthlyCtx {
    type Row<'a> = <<AuthlyCtx as GetDb>::Db as Db>::Row<'a>;

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
}
