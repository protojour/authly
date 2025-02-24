use authly_domain::extract::auth::WebAuth;
use axum::response::{IntoResponse, Response};
use http::{
    header::{InvalidHeaderValue, LOCATION},
    HeaderValue, StatusCode,
};
use maud::{html, Markup, DOCTYPE};
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

fn render_app_tab(Htmx { prefix, .. }: &Htmx, tab: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly" }
                script src={(prefix)"/static/vendor/htmx.min.js"} {}
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
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("invalid header value")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        warn!(?self, "app error");

        (StatusCode::INTERNAL_SERVER_ERROR, "something went wrong").into_response()
    }
}
