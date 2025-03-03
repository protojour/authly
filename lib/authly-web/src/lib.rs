use authly_domain::{
    ctx::{
        Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetHttpClient, GetInstance, WebAuthn,
    },
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
        + WebAuthn
        + Clone
        + Send
        + Sync
        + 'static,
{
    axum::Router::new()
        .route("/", get(app::index))
        .route("/tab/persona", get(app::persona::persona::<Ctx>))
        .route(
            "/tab/persona/webauthn/register_start",
            post(app::persona::webauthn_register_start::<Ctx>),
        )
        .route(
            "/tab/persona/webauthn/register_finish",
            post(app::persona::webauthn_register_finish::<Ctx>),
        )
        .route("/auth", get(auth::index))
        .route("/auth/login", post(auth::login::<Ctx>))
        .route(
            "/auth/webauthn/finish",
            post(auth::webauthn_auth_finish::<Ctx>),
        )
        .route(
            "/auth/oauth/:label/callback",
            post(auth::oauth::oauth_callback::<Ctx>),
        )
        .nest_service("/static", static_folder())
}

mod htmx {
    use http::HeaderName;

    /// https://htmx.org/headers/hx-redirect/
    pub const HX_REDIRECT: HeaderName = HeaderName::from_static("hx-redirect");

    /// https://htmx.org/attributes/hx-request/
    #[expect(unused)]
    pub const HX_REQUEST: HeaderName = HeaderName::from_static("hx-request");

    /// https://htmx.org/headers/hx-trigger/
    pub const HX_TRIGGER: HeaderName = HeaderName::from_static("hx-trigger");

    /// https://htmx.org/reference/#response_headers
    pub const HX_REFRESH: HeaderName = HeaderName::from_static("hx-refresh");
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
