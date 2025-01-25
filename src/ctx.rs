//! Traits for abstracting away application context

use std::sync::Arc;

use crate::{db::Db, AuthlyCtx, TlsParams};

pub trait GetDb {
    type Db: Db;

    fn get_db(&self) -> &Self::Db;
}

pub trait GetTlsParams {
    fn get_tls_params(&self) -> &Arc<TlsParams>;
}

impl GetDb for AuthlyCtx {
    type Db = hiqlite::Client;

    fn get_db(&self) -> &Self::Db {
        &self.hql
    }
}

impl GetTlsParams for AuthlyCtx {
    fn get_tls_params(&self) -> &Arc<TlsParams> {
        &self.tls_params
    }
}
