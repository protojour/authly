use std::env;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::RequestPartsExt;
use axum::{http::request::Parts, routing::get};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use indoc::indoc;
use maud::{html, DOCTYPE};
use maud::{Markup, PreEscaped};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct Ctx {
    client: Option<authly_client::Client>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    info!("HELLO");

    // DISABLE_AUTHLY is nice when only working on the HTML
    let client = if env::var("DISABLE_AUTHLY").is_err() {
        let client = authly_client::Client::builder()
            .from_environment()
            .await
            .unwrap()
            .connect()
            .await
            .unwrap();

        let entity_id = client.entity_id().await.unwrap();
        let label = client.label().await.unwrap();

        info!("client running, entity_id={entity_id} label={label}");

        Some(client)
    } else {
        None
    };

    let ctx = Ctx { client };

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app(ctx)).await.unwrap();
}

fn app(ctx: Ctx) -> axum::Router {
    axum::Router::new()
        .route("/", get(index))
        .route("/tab/service", get(tab_service))
        .route("/tab/user", get(tab_user))
        .with_state(ctx)
}

enum Error {
    UserNotAuthenticated,
    Authly(authly_client::Error),
}

impl From<authly_client::Error> for Error {
    fn from(value: authly_client::Error) -> Self {
        Self::Authly(value)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::UserNotAuthenticated => StatusCode::UNAUTHORIZED.into_response(),
            Self::Authly(err) => {
                error!(?err, "authly client error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

async fn index(ctx: HtmlCtx) -> Markup {
    let js_error_handler = indoc! {
        r#"
        document.body.addEventListener('htmx:responseError', function(evt) {
            if (evt.detail.xhr.status == 401) {
                // login handler
                const next = encodeURIComponent(document.location.href);
                window.location.href = `/authly/web/auth/?next=${next}/`;
            } else {
                console.log('unhandled response error');
            }
        });
        "#,
    };
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly Testservice" }
                script src="https://unpkg.com/htmx.org@2.0.4" {}
                script src="https://unpkg.com/htmx-ext-json-enc@2.0.1/json-enc.js" {}
                link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css" {}
            }
            body {
                main class="container" {
                    h1 { "Authly Testservice" }
                    p {
                        "This is the web interface of " code { "authly-testservice" } ". "
                    }

                    div id="tabs" hx-get={(ctx.prefix)"/tab/service"} hx-trigger="load delay:100ms" hx-target="#tabs" hx-swap="innerHTML";
                }
            }

            script { (PreEscaped(js_error_handler)) }
        }
    }
}

async fn tab_service(ctx: HtmlCtx) -> Result<Markup, Error> {
    let (entity_id, label) = if let Some(client) = ctx.client.as_ref() {
        (client.entity_id().await?.to_string(), client.label().await?)
    } else {
        ("N/A".to_string(), "N/A".to_string())
    };

    Ok(html! {
        (render_nav_tab_list(0, &ctx))

        div id="tab-content" role="tabpanel" class="tab-content" {
            p {
                "The Authly Entity ID of this service is " code { (entity_id) } ". "
                "The Authly label is " code { (label) } ". "
            }
        }
    })
}

async fn tab_user(ctx: HtmlCtx) -> Result<Markup, Error> {
    let Some(access_token) = ctx.access_token.clone() else {
        return Err(Error::UserNotAuthenticated);
    };

    Ok(html! {
        (render_nav_tab_list(1, &ctx))

        div id="tab-content" role="tabpanel" class="tab-content" {
            p {
                "The Authly Entity ID of the user is " code { (access_token.claims.authly.entity_id) } ". "
            }
        }
    })
}

fn render_nav_tab_list(selected: usize, ctx: &HtmlCtx) -> Markup {
    let mut aria_current = [None, None];
    aria_current[selected] = Some("page");

    html! {
        nav {
            ul {
                li {
                    a hx-get={(ctx.prefix)"/tab/service"} aria-current=[aria_current[0]] role="tab" aria-controls="tab-content" {
                        "Service"
                    }
                }
                li {
                    a hx-get={(ctx.prefix)"/tab/user"} aria-current=[aria_current[1]] role="tab" aria-controls="tab-content" {
                        "User"
                    }
                }
            }
        }
    }
}

struct HtmlCtx {
    client: Option<authly_client::Client>,
    access_token: Option<Arc<authly_client::AccessToken>>,
    prefix: String,
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<Ctx> for HtmlCtx {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, ctx: &Ctx) -> Result<Self, Self::Rejection> {
        let client = ctx.client.clone();

        let opt_authorization = parts
            .extract::<Option<TypedHeader<Authorization<Bearer>>>>()
            .await
            .map_err(|_| Error::UserNotAuthenticated)?;

        let access_token = match (&client, opt_authorization) {
            (Some(client), Some(authorization)) => {
                Some(client.decode_access_token(authorization.token())?)
            }
            _ => None,
        };

        let prefix = if let Some(prefix) = parts.headers.get("x-forwarded-prefix") {
            if let Ok(prefix) = prefix.to_str() {
                prefix.to_string()
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };

        Ok(Self {
            client,
            access_token,
            prefix,
        })
    }
}
