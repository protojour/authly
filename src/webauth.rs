use axum::{extract::State, routing::get};
use http::request::Parts;
use indoc::indoc;
use maud::{html, Markup, PreEscaped, DOCTYPE};

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
) -> Markup {
    let css = indoc! {
        r#"
        #root {
            min-height: 100vh;
            height: fit-content;
            max-width: 100vw;
            display: grid;
            align-items: center;
            justify-content: center;
            grid-template-columns: minmanx(auto, 960px);
        }
        main {
            display: grid;
            place-items: center;
        }
        "#
    };
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly" }
                script src="https://unpkg.com/htmx.org@2.0.4" {}
                script src="https://unpkg.com/htmx-ext-json-enc@2.0.1/json-enc.js" {}
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2.0.6/css/pico.classless.min.css" {}
                style { (PreEscaped(css)) }
            }
            body {
                div id="root" {
                    main {
                        h1 { "Sign in with Authly" }
                        form hx-post={(prefix)"/api/auth/authenticate"} hx-ext="json-enc" {
                            input id="username" name="username" type="text" aria-label="Username" required {}
                            input id="password" name="password" type="password" aria-label="Password" required {}
                            button type="submit" { "Login" }
                        }
                    }
                }
            }
        }
    }
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
