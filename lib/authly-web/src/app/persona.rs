use std::collections::BTreeMap;

use authly_common::id::PersonaId;
use authly_domain::{
    ctx::{GetDb, GetDecryptedDeks, WebAuthn},
    extract::{auth::WebAuth, base_uri::ProxiedBaseUri},
    repo::webauthn_repo,
    webauthn::{self, RegisterPublicKeyCredential},
};
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Form,
};
use indoc::formatdoc;
use maud::{html, Markup};
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use tracing::info;

use crate::{
    app::tabs::{render_nav_tab_list, Tab},
    htmx::{HX_REFRESH, HX_TRIGGER},
    Htmx,
};

use super::{render_app_tab, AppError};

pub async fn persona<Ctx>(
    State(ctx): State<Ctx>,
    htmx: Htmx,
    auth: WebAuth<()>,
) -> Result<Markup, AppError>
where
    Ctx: GetDb,
{
    let prefix = &htmx.prefix;
    let eid = auth.claims.authly.entity_id;

    let passkeys = if let Ok(persona_id) = PersonaId::try_from(eid) {
        webauthn_repo::list_passkeys_by_entity_id(ctx.get_db(), persona_id)
            .await
            .map(Some)
            .map_err(|err| AppError::Internal(err.into()))?
    } else {
        None
    };

    Ok(render_app_tab(
        &htmx,
        html! {
            (render_nav_tab_list(Tab::Persona, &prefix))

            div id="tab-content" role="tabpanel" class="tab-content" {
                p {
                    "entity ID: " code { (eid) }
                }

                section {
                    h4 { "WebAuthn" }

                    @if let Some(passkeys) = passkeys {
                        table {
                            thead {
                                tr {
                                    th { "ID" }
                                    th { "Created" }
                                    th { "Last used" }
                                }
                            }
                            tbody {
                                @for row in passkeys {
                                    tr {
                                        td { code { (serde_plain::to_string(row.passkey.cred_id())?) } }
                                        td { relative-time datetime=(row.created.format(&Rfc3339)?) {} }
                                        td {
                                            @if let Some(last_used) = row.last_used {
                                                relative-time datetime=(last_used.format(&Rfc3339)?) {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div id="passkeyreg" {
                        button hx-post={(prefix)"/tab/persona/webauthn/register_start"} hx-target="#passkeyreg" {
                            "Register new Passkey"
                        }
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
                            target: '#passkeyreg',
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
        div id="passkeyreg" {
            "registering.."
        }
    };

    Ok(([(HX_TRIGGER, hx_event_json)], html).into_response())
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

    Ok((
        [(HX_REFRESH, "true")],
        html! {
            div id="passkeyreg" {
                "success!"
            }
        },
    )
        .into_response())
}
