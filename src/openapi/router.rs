use axum::{routing::post, Router};

use crate::AuthlyCtx;

use super::{admin, user_auth};

pub fn router() -> Router<AuthlyCtx> {
    Router::new()
        .route("/api/auth/authenticate", post(user_auth::authenticate))
        .route("/api/admin/document", post(admin::post_document))
}
