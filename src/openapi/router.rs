use axum::{routing::post, Router};

use crate::AuthlyCtx;

use super::{admin, user_auth};

/// Router under /api/
pub fn openapi_router(ctx: AuthlyCtx) -> Router {
    Router::new()
        .route("/auth/authenticate", post(user_auth::authenticate))
        .route("/admin/document", post(admin::post_document))
        .with_state(ctx)
}
