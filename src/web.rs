use authly_webstatic::static_folder;
use axum::routing::{get, post};

use crate::AuthlyCtx;

pub mod app;
pub mod auth;

pub fn router() -> axum::Router<AuthlyCtx> {
    axum::Router::new()
        // Currently a quirk in the gateway requires this route to be added twice
        // (`/` is appended by the gateway because /web is a "matcher", => /web/)
        .route("/web", get(app::index))
        .route("/web/", get(app::index))
        .route("/web/auth", get(auth::index))
        .route("/web/auth/login", post(auth::login))
        .route(
            "/web/auth/oauth/:label/callback",
            post(auth::oauth::oauth_callback),
        )
        .nest_service("/web/static", static_folder())
}
