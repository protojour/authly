use authly_domain::ctx::{
    Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetHttpClient, GetInstance,
};
use authly_webstatic::static_folder;
use axum::routing::{get, post};

pub mod app;
pub mod auth;

pub fn router<Ctx>() -> axum::Router<Ctx>
where
    Ctx: GetDb
        + GetInstance
        + GetBuiltins
        + GetDecryptedDeks
        + Directories
        + GetHttpClient
        + Clone
        + Send
        + Sync
        + 'static,
{
    axum::Router::new()
        .route("/", get(app::index))
        .route("/tab/persona", get(app::persona::persona))
        .route("/auth", get(auth::index))
        .route("/auth/login", post(auth::login::<Ctx>))
        .route(
            "/auth/oauth/:label/callback",
            post(auth::oauth::oauth_callback),
        )
        .nest_service("/static", static_folder())
}
