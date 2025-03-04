use std::collections::BTreeMap;

use authly_common::mtls_server::PeerServiceEntity;
use authly_domain::{
    ctx::{GetBuiltins, GetDb, GetDecryptedDeks, WebAuthn},
    dev::IsDev,
    extract::base_uri::{ForwardedPrefix, ProxiedBaseUri},
    login::{try_username_password_login, LoginError, LoginOptions},
    login_session::LoginSession,
    session::Session,
    webauthn::{self, PublicKeyCredential},
};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    Extension, Form,
};
use http::{StatusCode, Uri};
use indoc::formatdoc;
use maud::{html, Markup, PreEscaped, DOCTYPE};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::htmx::{HX_REDIRECT, HX_TRIGGER};

pub mod oauth;

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryParams {
    #[serde(default)]
    next: String,
}

pub async fn index(
    ForwardedPrefix(prefix): ForwardedPrefix,
    login_session: LoginSession,
    Query(params): Query<QueryParams>,
) -> Response {
    (
        axum_extra::extract::CookieJar::new().add(login_session.to_cookie()),
        html! {
            (DOCTYPE)
            html {
                head {
                    meta charset="utf-8";
                    meta name="viewport" content="device-width, intial-scale=1";
                    meta name="color-scheme" content="light dark";
                    title { "Authly sign in" }
                    script src={(prefix)"/static/vendor/htmx.min.js"} {}
                    script src={(prefix)"/static/vendor/base64.min.js"} {}
                    link rel="shortcut icon" href={(prefix)"/static/favicon.svg"} type="image/svg+xml";
                    link rel="stylesheet" href={(prefix)"/static/vendor/pico.classless.min.css"};
                    link rel="stylesheet" href={(prefix)"/static/style.css"};
                    link rel="stylesheet" href={(prefix)"/static/auth.css"};
                }
                body {
                    div id="root" {
                        main {
                            img alt="Authly" src={(prefix)"/static/logo.svg"};
                            div class="card" {
                                h2 { "Sign in" }
                                (login_form(&prefix, &params, None))
                            }
                        }
                    }
                }

                script { (PreEscaped(render_script(&prefix, &params))) }
            }
        }
    )
    .into_response()
}

fn render_script(prefix: &str, params: &QueryParams) -> String {
    let webauthn_finish_url = format!(
        "{prefix}/auth/webauthn/finish?{}",
        &serde_urlencoded::to_string(params).unwrap()
    );

    formatdoc! {
        r#"
        document.body.addEventListener('webauthnAuthStart', function(evt) {{
            const detail = evt.detail;

            detail.publicKey.challenge = Base64.toUint8Array(detail.publicKey.challenge);
            detail.publicKey.allowCredentials?.forEach(function (listItem) {{
                listItem.id = Base64.toUint8Array(listItem.id)
            }});

            window.navigator.credentials.get({{ publicKey: detail.publicKey }}).then((assertion) => {{
                htmx.ajax('POST', '{webauthn_finish_url}',
                    {{
                        target: '#loginform',
                        values: {{
                            json: JSON.stringify({{
                                id: assertion.id,
                                rawId: Base64.fromUint8Array(new Uint8Array(assertion.rawId), true),
                                type: assertion.type,
                                response: {{
                                    authenticatorData: Base64.fromUint8Array(new Uint8Array(assertion.response.authenticatorData), true),
                                    clientDataJSON: Base64.fromUint8Array(new Uint8Array(assertion.response.clientDataJSON), true),
                                    signature: Base64.fromUint8Array(new Uint8Array(assertion.response.signature), true),
                                    userHandle: Base64.fromUint8Array(new Uint8Array(assertion.response.userHandle), true)
                                }},
                            }})
                        }}
                    }}
                );
            }});
        }});
        "#
    }
}

/// A login form with an optional error message
fn login_form(prefix: &str, params: &QueryParams, message: Option<&str>) -> Markup {
    let login_url = format!(
        "{prefix}/auth/login?{}",
        &serde_urlencoded::to_string(params).unwrap()
    );

    html!(
        form id="loginform" hx-post={(login_url)} {
            div class="inputs" {
                input id="username" name="username" type="text" aria-label="Username" placeholder="Username" required autofocus {}
                input id="password" name="password" type="password" aria-label="Password" placeholder="Password" {}
            }
            @if let Some(message) = message {
                div class="error" {
                    (message)
                }
            }
            div id="login_submit" {
                button type="submit" name="action" value="login" {
                    svg {
                        use href={(prefix)"/static/vendor/login.svg#icon"};
                    }
                    "Sign in"
                }

                button type="submit" name="action" value="webauthn" {
                    svg {
                        use href={(prefix)"/static/vendor/login.svg#icon"};
                    }
                    "Passwordless"
                }
            }
        }
    )
}

// NOTE: This is currently sent "unencrypted" and can be MITMed by whoever terminates SSL outside Authly's control,
// when the web auth routes are exposed on the internet.
#[derive(Deserialize)]
pub struct LoginBody {
    action: String,
    username: String,
    password: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn login<Ctx>(
    State(ctx): State<Ctx>,
    Extension(peer_svc): Extension<PeerServiceEntity>,
    login_session: LoginSession,
    is_dev: IsDev,
    base_uri: ProxiedBaseUri,
    ForwardedPrefix(prefix): ForwardedPrefix,
    Query(params): Query<QueryParams>,
    Form(LoginBody {
        action,
        username,
        password,
    }): Form<LoginBody>,
) -> Response
where
    Ctx: GetDb + GetBuiltins + GetDecryptedDeks + WebAuthn,
{
    /// Produce a "hx-trigger" header value that starts webauthn auth flow
    async fn webauthn_start_event_header_value(
        ctx: &(impl WebAuthn + GetDb + GetDecryptedDeks),
        base_uri: &Uri,
        login_session: LoginSession,
        username: &str,
    ) -> anyhow::Result<String> {
        let challenge_response =
            webauthn::webauthn_start_authentication(ctx, base_uri, login_session.0, username)
                .await?;
        let hx_event = BTreeMap::from_iter([("webauthnAuthStart", challenge_response)]);
        let hx_event_json = serde_json::to_string(&hx_event)?;

        Ok(hx_event_json)
    }

    match action.as_str() {
        "login" => {
            let login_options = LoginOptions::default().dev(is_dev);

            match try_username_password_login(&ctx, peer_svc, username, password, login_options)
                .await
            {
                Ok((_persona_id, session)) => login_success_redirect(session, &params),
                Err(err) => {
                    match err {
                        LoginError::UnprivilegedService => info!("unprivileged service"),
                        LoginError::Credentials => {}
                        LoginError::Db(err) => warn!(?err, "login db error"),
                    }

                    login_form(&prefix, &params, Some("Invalid username or password"))
                        .into_response()
                }
            }
        }
        "webauthn" => {
            match webauthn_start_event_header_value(&ctx, &base_uri.0, login_session, &username)
                .await
            {
                Ok(trigger_event_value) => (
                    [(HX_TRIGGER, trigger_event_value)],
                    login_form(&prefix, &params, None),
                )
                    .into_response(),
                Err(err) => {
                    tracing::error!(?err, "webauthn auth");

                    login_form(&prefix, &params, Some("Webauthn error")).into_response()
                }
            }
        }
        _ => login_form(&prefix, &params, Some("Invalid login action")).into_response(),
    }
}

fn login_success_redirect(session: Session, params: &QueryParams) -> Response {
    (
        axum_extra::extract::CookieJar::new().add(session.to_cookie()),
        [(HX_REDIRECT, &params.next)],
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct PublicKeyCredentialForm {
    /// The PublicKeyCredential JSON string
    json: String,
}

pub async fn webauthn_auth_finish<Ctx>(
    State(ctx): State<Ctx>,
    Extension(_peer_svc): Extension<PeerServiceEntity>,
    login_session: LoginSession,
    base_uri: ProxiedBaseUri,
    ForwardedPrefix(prefix): ForwardedPrefix,
    Query(params): Query<QueryParams>,
    Form(PublicKeyCredentialForm { json }): Form<PublicKeyCredentialForm>,
) -> Result<Response, (StatusCode, String)>
where
    Ctx: GetDb + WebAuthn + GetBuiltins,
{
    let credential = serde_json::from_str::<PublicKeyCredential>(&json)
        .map_err(|err| (StatusCode::UNPROCESSABLE_ENTITY, format!("{err:?}")))?;

    match webauthn::webauthn_finish_authentication(&ctx, &base_uri.0, login_session.0, credential)
        .await
    {
        Ok((_persona_id, session)) => Ok(login_success_redirect(session, &params)),
        Err(err) => {
            info!(?err, "webauthn auth finish error");
            Ok(login_form(&prefix, &params, Some("webauthn auth error")).into_response())
        }
    }
}
