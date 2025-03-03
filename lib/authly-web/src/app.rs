use authly_domain::extract::auth::WebAuth;
use axum::response::{IntoResponse, Response};
use http::{
    header::{InvalidHeaderValue, LOCATION},
    HeaderValue, StatusCode,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use tracing::warn;

use crate::{htmx::HX_REDIRECT, Htmx};

pub mod persona;

mod tabs;

/// The "index.html" of the Authly web app
/// Just redirects to the default tab.
pub async fn index(
    Htmx { prefix, hx_request }: Htmx,
    _auth: WebAuth<()>,
) -> Result<Response, AppError> {
    Ok((
        StatusCode::FOUND,
        [(
            if hx_request { HX_REDIRECT } else { LOCATION },
            HeaderValue::from_str(&format!("{prefix}/tab/persona"))?,
        )],
    )
        .into_response())
}

fn render_app_tab(Htmx { prefix, .. }: &Htmx, tab: Markup, js: Option<String>) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly" }
                script src={(prefix)"/static/vendor/htmx.min.js"} {}
                script src={(prefix)"/static/vendor/base64.min.js"} {}
                // The relative-time Web Component:
                script type="module" src={(prefix)"/static/vendor/relative-time-element-bundle.js"} {}

                link rel="shortcut icon" href={(prefix)"/static/favicon.svg"} type="image/svg+xml";
                link rel="stylesheet" href={(prefix)"/static/vendor/pico.classless.min.css"};
                link rel="stylesheet" href={(prefix)"/static/style.css"};
                link rel="stylesheet" href={(prefix)"/static/app.css"};
            }
            body {
                main {
                    img alt="Authly" src={(prefix)"/static/logo.svg"};

                    (tab)
                }
            }

            @if let Some(js) = js {
                script { (PreEscaped(js)) }
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("must be persona")]
    MustBePersona,
    #[error("invalid header value")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("invalid input: {0}")]
    InvalidInput(anyhow::Error),
    #[error("internal: {0}")]
    Internal(anyhow::Error),
    #[error("date format: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("plain format: {0}")]
    SerdePlain(#[from] serde_plain::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        warn!(?self, "app error");

        (StatusCode::INTERNAL_SERVER_ERROR, "something went wrong").into_response()
    }
}
