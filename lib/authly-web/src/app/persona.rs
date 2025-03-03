use std::collections::BTreeMap;

use authly_domain::{
    ctx::{GetDb, GetDecryptedDeks, WebAuthn},
    extract::{auth::WebAuth, base_uri::ProxiedBaseUri},
    webauthn::{self, RegisterPublicKeyCredential},
};
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Form,
};
use http::HeaderValue;
use indoc::formatdoc;
use maud::{html, Markup};
use serde::Deserialize;
use tracing::info;

use crate::{
    app::tabs::{render_nav_tab_list, Tab},
    htmx::HX_TRIGGER,
    Htmx,
};

use super::{render_app_tab, AppError};

pub async fn persona(htmx: Htmx, auth: WebAuth<()>) -> Result<Markup, AppError> {
    let prefix = &htmx.prefix;
    let eid = auth.claims.authly.entity_id;

    Ok(render_app_tab(
        &htmx,
        html! {
            (render_nav_tab_list(Tab::Persona, &prefix))

            div id="tab-content" role="tabpanel" class="tab-content" {
                div {
                    "entity ID: " code { (eid) }
                }

                div id="webauthn" {
                    button hx-post={(prefix)"/tab/persona/webauthn/register_start"} hx-target="#webauthn" {
                        "Register WebAuthn token"
                    }
                }
            }
        },
        Some(formatdoc! {
            r#"
            document.body.addEventListener('webauthnRegisterStart', function(evt) {{
                console.log("registering");
                const detail = evt.detail;

                detail.publicKey.challenge = Base64.toUint8Array(detail.publicKey.challenge);
                detail.publicKey.user.id = Base64.toUint8Array(detail.publicKey.user.id);
                detail.publicKey.excludeCredentials?.forEach(function (listItem) {{
                    listItem.id = Base64.toUint8Array(listItem.id)
                }});

                window.navigator.credentials.create(detail).then((credential) => {{
                    console.log("registered");
                    console.log(credential);
                    htmx.ajax('POST', '{prefix}/tab/persona/webauthn/register_finish',
                        {{
                            target: '#webauthn',
                            values: {{
                                json: JSON.stringify({{
                                    id: credential.id,
                                    rawId: Base64.fromUint8Array(new Uint8Array(credential.rawId), true),
                                    type: credential.type,
                                    response: {{
                                        attestationObject: Base64.fromUint8Array(new Uint8Array(credential.response.attestationObject), true),
                                        clientDataJSON: Base64.fromUint8Array(new Uint8Array(credential.response.clientDataJSON), true),
                                    }},
                                }})
                            }}
                        }}
                    );
                }});
            }});
            "#,
        }),
    ))
}

pub async fn webauthn_register_start<Ctx>(
    State(ctx): State<Ctx>,
    base_uri: ProxiedBaseUri,
    auth: WebAuth<()>,
) -> Result<Response, AppError>
where
    Ctx: GetDb + WebAuthn + GetDecryptedDeks,
{
    let persona_id = auth
        .claims
        .authly
        .entity_id
        .try_into()
        .map_err(|_| AppError::MustBePersona)?;

    let challenge_response = webauthn::webauthn_start_registration(&ctx, &base_uri.0, persona_id)
        .await
        .map_err(|err| AppError::Internal(err.into()))?;
    let hx_event = BTreeMap::from_iter([("webauthnRegisterStart", challenge_response)]);
    let hx_event_json =
        serde_json::to_string(&hx_event).map_err(|err| AppError::Internal(err.into()))?;

    let html = html! {
        div id="webauthn" {
            "registering.."
        }
    };

    Ok((
        [(HX_TRIGGER, HeaderValue::from_str(&hx_event_json).unwrap())],
        html,
    )
        .into_response())
}

/// This is an urlencoded form, which contains a JSON-encoded `RegisterPublicKeyCredential` inside.
/// The reason it works this way (now) is that I couldn't figure out how to trigger a POST/json js-triggered Ajax request from htmx.
#[derive(Deserialize)]
pub struct RegisterPublicKeyCredentialForm {
    /// The RegisterPublicKeyCredential JSON string
    json: String,
}

pub async fn webauthn_register_finish<Ctx>(
    State(ctx): State<Ctx>,
    base_uri: ProxiedBaseUri,
    auth: WebAuth<()>,
    Form(form): Form<RegisterPublicKeyCredentialForm>,
) -> Result<Response, AppError>
where
    Ctx: GetDb + WebAuthn,
{
    let persona_id = auth
        .claims
        .authly
        .entity_id
        .try_into()
        .map_err(|_| AppError::MustBePersona)?;
    let credential: RegisterPublicKeyCredential =
        serde_json::from_str(&form.json).map_err(|err| AppError::InvalidInput(err.into()))?;

    webauthn::webauthn_finish_registration(&ctx, &base_uri.0, persona_id, credential)
        .await
        .map_err(|err| AppError::Internal(err.into()))?;

    info!(?persona_id, "passkey registered");

    Ok(html! {
        div id="webauthn" {
            "success!"
        }
    }
    .into_response())
}
