use axum::{routing::post, Router};

use crate::AuthlyCtx;

use super::{admin, user_auth};

pub fn openapi_router(ctx: AuthlyCtx) -> Router {
    Router::new()
        .route("/api/auth/authenticate", post(user_auth::authenticate))
        .route("/api/admin/document", post(admin::post_document))
        .with_state(ctx.clone())
}
