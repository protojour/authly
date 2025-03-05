use std::collections::BTreeMap;

use authly_common::id::PersonaId;
use authly_domain::{
    ctx::{GetDb, GetDecryptedDeks, WebAuthn},
    extract::{auth::WebAuth, base_uri::ProxiedBaseUri},
    repo::webauthn_repo,
    webauthn::{self, RegisterPublicKeyCredential, WebauthnError},
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
use tracing::{info, warn};

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

                    (render_passkeyreg(&htmx, false, None))
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
    htmx: Htmx,
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

    let html = render_passkeyreg(&htmx, true, None);

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
    htmx: Htmx,
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

    match webauthn::webauthn_finish_registration(&ctx, &base_uri.0, persona_id, credential).await {
        Ok(_) => {
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
        Err(err) => {
            warn!(?err, "WebAuthn registration error");

            let msg = match err {
                WebauthnError::NotSupported => "Not supported".to_string(),
                WebauthnError::NoSession => "No WebAuthn server session was found".to_string(),
                WebauthnError::Webauthn(err) => format!("WebAuthn error: {err:?}"),
                // Don't expose other internal errors
                _err => "Internal error".to_string(),
            };

            Ok(render_passkeyreg(&htmx, false, Some(msg)).into_response())
        }
    }
}

/// Render the "passkeyreg" div
fn render_passkeyreg(htmx: &Htmx, registering: bool, error: Option<String>) -> Markup {
    let prefix = &htmx.prefix;

    html! {
        div id="passkeyreg" {
            @if let Some(error) = error {
                article {
                    "Passkey registration error: " code { (error) }
                }
            }

            @if registering {
                button aria-busy="true" {
                    "Registering.."
                }
            } @else {
                button hx-post={(prefix)"/tab/persona/webauthn/register_start"} hx-target="#passkeyreg" {
                    "Register new Passkey"
                }
            }
        }
    }
}
