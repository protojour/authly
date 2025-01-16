use axum::{extract::State, response::Html, routing::get};
use http::request::Parts;
use indoc::formatdoc;

use crate::AuthlyCtx;

pub fn router() -> axum::Router<AuthlyCtx> {
    axum::Router::new()
        // Currently a quirk in the gateway requires this route to be added twice
        // (`/` is appended by the gateway because /web/auth is a "matcher", => /web/auth/)
        .route("/web/auth", get(index))
        .route("/web/auth/", get(index))
}

pub async fn index(
    State(_ctx): State<AuthlyCtx>,
    ForwardedPrefix(prefix): ForwardedPrefix,
) -> Html<String> {
    Html(formatdoc! {
        r#"
        <!DOCTYPE html>
        <script src="https://unpkg.com/htmx.org@2.0.4"></script>
        <script src="https://unpkg.com/htmx-ext-json-enc@2.0.1/json-enc.js"></script>
        <form hx-post="{prefix}/api/auth/authenticate" hx-ext="json-enc">
            <div>
                Username:
                <input id="username" name="username" type="text">
            </div>
            <div>
                Password:
                <input id="password" name="password" type="password">
            </div>
            <button type="submit">Login</button>
        </form>
        "#,
    })
}

#[derive(Default)]
pub struct ForwardedPrefix(String);

#[axum::async_trait]
impl axum::extract::FromRequestParts<AuthlyCtx> for ForwardedPrefix {
    type Rejection = ();

    /// Perform the extraction.
    async fn from_request_parts(
        parts: &mut Parts,
        _ctx: &AuthlyCtx,
    ) -> Result<Self, Self::Rejection> {
        let Some(prefix) = parts.headers.get("x-forwarded-prefix") else {
            return Ok(Self::default());
        };

        let Ok(prefix) = prefix.to_str() else {
            return Ok(Self::default());
        };

        Ok(Self(prefix.to_string()))
    }
}
