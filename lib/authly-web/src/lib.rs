use authly_domain::{
    ctx::{Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetHttpClient, GetInstance},
    extract::base_uri::ForwardedPrefix,
};
use authly_webstatic::static_folder;
use axum::{
    async_trait,
    routing::{get, post},
};
use http::request::Parts;

pub mod app;
pub mod auth;

#[cfg(test)]
mod tests;

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

mod htmx {
    use http::HeaderName;

    pub const HX_REDIRECT: HeaderName = HeaderName::from_static("hx-redirect");

    #[expect(unused)]
    pub const HX_REQUEST: HeaderName = HeaderName::from_static("hx-request");
}

#[derive(Clone)]
pub struct Htmx {
    hx_request: bool,
    prefix: String,
}

#[async_trait]
impl<S: Sync> axum::extract::FromRequestParts<S> for Htmx {
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let prefix = ForwardedPrefix::from_request_parts(parts, state).await?;

        Ok(Self {
            hx_request: parts.headers.contains_key("hx-request"),
            prefix: prefix.0,
        })
    }
}
