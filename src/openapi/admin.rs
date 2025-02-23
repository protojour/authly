use authly_common::document::Document;
use authly_domain::{
    access_control,
    audit::Actor,
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    extract::{auth::ApiAuth, base_uri::ProxiedBaseUri},
};
use authly_service::authority_mandate::submission;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use tracing::warn;

use crate::{directory, AuthlyCtx};

// FIXME: User-friendly document errors
// TODO: Handle unchanged documents like in load.rs
pub async fn post_document(
    State(ctx): State<AuthlyCtx>,
    auth: ApiAuth<access_control::role::ApplyDocument>,
    body: String,
) -> Result<Response, Response> {
    let doc = Document::from_toml(&body)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid toml").into_response())?;

    let meta = DocumentMeta {
        url: format!("admin://user/?entity_id={}", auth.claims.authly.entity_id),
        hash: {
            let mut hasher = blake3::Hasher::new();
            hasher.update(body.as_bytes());
            hasher.finalize().into()
        },
    };

    let compiled_doc = compile_doc(&ctx, doc, meta)
        .await
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid document").into_response())?;

    directory::apply_document(&ctx, compiled_doc, Actor(auth.claims.authly.entity_id))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "authority application error",
            )
                .into_response()
        })?;

    Ok((StatusCode::OK, "document applied").into_response())
}

pub async fn post_authority_mandate_submission_token(
    State(ctx): State<AuthlyCtx>,
    auth: ApiAuth<access_control::role::GrantMandate>,
    proxied_base_uri: ProxiedBaseUri,
) -> Result<Response, Response> {
    let token = submission::authority::authority_generate_submission_token(
        &ctx,
        proxied_base_uri.to_string(),
        Actor(auth.claims.authly.entity_id),
        None,
    )
    .await
    .map_err(|err| {
        warn!(?err, "unable to create submission token");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    Ok(token.into_response())
}
