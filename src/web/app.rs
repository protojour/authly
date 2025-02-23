use authly_domain::extract::{auth::WebAuth, base_uri::ForwardedPrefix};
use axum::response::IntoResponse;
use maud::{html, Markup, DOCTYPE};

pub mod persona;

mod tabs;

pub enum AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        "something went wrong".into_response()
    }
}

/// The "index.html" of the Authly web app
pub async fn index(_auth: WebAuth<()>, ForwardedPrefix(prefix): ForwardedPrefix) -> Markup {
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

                    div id="tabs" hx-get={(prefix)"/tab/persona"} hx-trigger="load delay:100ms" hx-target="#tabs" hx-swap="innerHTML";
                }
            }
        }
    }
}
