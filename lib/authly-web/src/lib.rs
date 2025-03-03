use authly_domain::{
    ctx::{
        Directories, GetBuiltins, GetDb, GetDecryptedDeks, GetHttpClient, GetInstance, WebAuthn,
    },
    extract::base_uri::ForwardedPrefix,
};
use authly_webstatic::static_folder;
use axum::{
    async_trait,
    extract::FromRef,
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
        .route("/tab/persona", get(app::persona::persona))
        .route(
            "/tab/persona/webauthn/register_start",
            post(app::persona::webauthn_register_start),
        )
        .route(
            "/tab/persona/webauthn/register_finish",
            post(app::persona::webauthn_register_finish),
        )
        .route("/auth", get(auth::index))
        .route("/auth/login", post(auth::login::<Ctx>))
        .route(
            "/auth/oauth/:label/callback",
            post(auth::oauth::oauth_callback),
        )
        .nest_service("/static", static_folder())
}

pub struct Authly<Ctx>(pub Ctx);

impl<Ctx> FromRef<Ctx> for Authly<Ctx>
where
    Ctx: GetDb + Directories + Clone,
{
    fn from_ref(input: &Ctx) -> Self {
        Self(input.clone())
    }
}

mod htmx {
    use http::HeaderName;

    pub const HX_REDIRECT: HeaderName = HeaderName::from_static("hx-redirect");

    #[expect(unused)]
    pub const HX_REQUEST: HeaderName = HeaderName::from_static("hx-request");

    pub const HX_TRIGGER: HeaderName = HeaderName::from_static("hx-trigger");
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
