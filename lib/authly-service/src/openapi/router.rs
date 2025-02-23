use authly_domain::ctx::{
    ClusterBus, Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetInstance, KubernetesConfig,
};
use axum::{routing::post, Router};

use super::{admin, user_auth};

pub fn router<Ctx>() -> Router<Ctx>
where
    Ctx: GetDb
        + GetInstance
        + GetBuiltins
        + GetDecryptedDeks
        + Directories
        + ClusterBus
        + KubernetesConfig
        + Clone
        + Send
        + Sync
        + 'static,
{
    Router::new()
        .route(
            "/api/auth/authenticate",
            post(user_auth::authenticate::<Ctx>),
        )
        .route("/api/admin/document", post(admin::post_document::<Ctx>))
        .route(
            "/api/admin/mandate/submission_token",
            post(admin::post_authority_mandate_submission_token::<Ctx>),
        )
}
