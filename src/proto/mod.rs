use tracing::warn;

use crate::db::DbError;

pub mod connect_server;
pub mod service_server;

impl From<DbError> for tonic::Status {
    fn from(err: DbError) -> Self {
        warn!(?err, "gRPC db error");
        tonic::Status::internal("db error")
    }
}
