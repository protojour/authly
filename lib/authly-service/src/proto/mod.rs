use authly_db::DbError;
use tracing::warn;

pub mod mandate_submission;
pub mod service_server;

fn grpc_db_err(err: DbError) -> tonic::Status {
    warn!(?err, "gRPC DbError");
    tonic::Status::internal("internal error")
}
