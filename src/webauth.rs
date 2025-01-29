use authly_webstatic::static_folder;
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
        .nest_service("/web/static", static_folder())
}

pub async fn index(
    State(_ctx): State<AuthlyCtx>,
    ForwardedPrefix(prefix): ForwardedPrefix,
) -> Markup {
    let js = indoc! {
        r#"
        document.body.addEventListener('htmx:afterRequest', function(evt) {
            if (evt.detail.pathInfo.requestPath.endsWith('/api/auth/authenticate')) {
                // redirect back to requesting app.
                const next = new URLSearchParams(window.location.search).get('next');
                if (next) {
                    window.location.href = next;
                }
            }
        });
        "#
    };

    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly sign in" }
                script src={(prefix)"/web/static/vendor/htmx.min.js"} {}
                script src={(prefix)"/web/static/vendor/json-enc.js"} {}
                link rel="shortcut icon" href={(prefix)"/web/static/favicon.svg"} type="image/svg+xml";
                link rel="stylesheet" href={(prefix)"/web/static/vendor/pico.classless.min.css"};
                link rel="stylesheet" href={(prefix)"/web/static/style.css"};
            }
            body {
                div id="root" {
                    main {
                        img alt="Authly" src={(prefix)"/web/static/logo.svg"};
                        div class="card" {
                            h2 { "Sign in" }
                            form hx-post={(prefix)"/api/auth/authenticate"} hx-ext="json-enc" {
                                div class="inputs" {
                                    input id="username" name="username" type="text" aria-label="Username" placeholder="Username" required autofocus {}
                                    input id="password" name="password" type="password" aria-label="Password" placeholder="Password" required {}
                                }
                                div {
                                    button type="submit" {
                                        svg {
                                            use href={(prefix)"/web/static/vendor/login.svg#icon"};
                                        }
                                        "Sign in"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            script { (PreEscaped(js)) }
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
