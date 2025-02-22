use authly_webstatic::static_folder;
use axum::routing::{get, post};

use crate::AuthlyCtx;

pub mod app;
pub mod auth;

pub fn router() -> axum::Router<AuthlyCtx> {
    axum::Router::new()
        // Currently a quirk in the gateway requires this route to be added twice
        // (`/` is appended by the gateway because "" is a matcher, => /)
        // .route("", get(app::index))
        .route("/", get(app::index))
        .route("/tab/persona", get(app::persona::persona))
        .route("/auth", get(auth::index))
        .route("/auth/login", post(auth::login))
        .route(
            "/auth/oauth/:label/callback",
            post(auth::oauth::oauth_callback),
        )
        .nest_service("/static", static_folder())
}
