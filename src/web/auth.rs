use authly_common::mtls_server::PeerServiceEntity;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    Extension, Form,
};
use http::{request::Parts, HeaderName, HeaderValue};
use maud::{html, Markup, DOCTYPE};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub mod oauth;

use crate::{
    login::{try_username_password_login, LoginError, LoginOptions},
    util::dev::IsDev,
    AuthlyCtx,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryParams {
    #[serde(default)]
    next: String,
}

pub async fn index(
    ForwardedPrefix(prefix): ForwardedPrefix,
    Query(params): Query<QueryParams>,
) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="device-width, intial-scale=1";
                meta name="color-scheme" content="light dark";
                title { "Authly sign in" }
                script src={(prefix)"/web/static/vendor/htmx.min.js"} {}
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
                            (login_form(&prefix, &params, None))
                        }
                    }
                }
            }
        }
    }
}

/// A login form with an optional error message
fn login_form(prefix: &str, params: &QueryParams, message: Option<&str>) -> Markup {
    let login_url = format!(
        "{prefix}/web/auth/login?{}",
        &serde_urlencoded::to_string(params).unwrap()
    );

    html!(
        form hx-post={(login_url)} {
            div class="inputs" {
                input id="username" name="username" type="text" aria-label="Username" placeholder="Username" required autofocus {}
                input id="password" name="password" type="password" aria-label="Password" placeholder="Password" required {}
            }
            @if let Some(message) = message {
                div class="error" {
                    (message)
                }
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
    )
}

// NOTE: This is currently sent "unencrypted" and can be MITMed by whoever terminates SSL outside Authly's control,
// when the web auth routes are exposed on the internet.
#[derive(Deserialize)]
pub struct LoginBody {
    username: String,
    password: String,
}

// NOTE: Uses response header `HX-redirect` (https://htmx.org/headers/hx-redirect/)
pub async fn login(
    State(ctx): State<AuthlyCtx>,
    Extension(peer_svc): Extension<PeerServiceEntity>,
    is_dev: IsDev,
    ForwardedPrefix(prefix): ForwardedPrefix,
    Query(params): Query<QueryParams>,
    Form(LoginBody { username, password }): Form<LoginBody>,
) -> Response {
    let login_options = LoginOptions::default().dev(is_dev);

    match try_username_password_login(&ctx, peer_svc, username, password, login_options).await {
        Ok((_persona_id, session)) => (
            axum_extra::extract::CookieJar::new().add(session.to_cookie()),
            [(
                HeaderName::from_static("hx-redirect"),
                HeaderValue::from_str(&params.next).unwrap_or_else(|err| {
                    warn!(
                        ?err,
                        ?params,
                        "client tried to fool us with a misformatted redirect url"
                    );
                    HeaderValue::from_static("")
                }),
            )],
        )
            .into_response(),
        Err(err) => {
            match err {
                LoginError::UnprivilegedService => info!("unprivileged service"),
                LoginError::Credentials => {}
                LoginError::Db(err) => warn!(?err, "login db error"),
            }

            login_form(&prefix, &params, Some("Invalid username or password")).into_response()
        }
    }
}

#[derive(Default)]
pub struct ForwardedPrefix(String);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for ForwardedPrefix {
    type Rejection = ();

    /// Perform the extraction.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(prefix) = parts.headers.get("x-forwarded-prefix") else {
            return Ok(Self::default());
        };

        let Ok(prefix) = prefix.to_str() else {
            return Ok(Self::default());
        };

        Ok(Self(prefix.to_string()))
    }
}
