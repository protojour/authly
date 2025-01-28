use std::marker::PhantomData;

use authly_common::{
    access_token::AuthlyAccessTokenClaims, document::Document, mtls_server::PeerServiceEntity,
};
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension, RequestPartsExt,
};
use http::{request::Parts, StatusCode};
use tracing::warn;

use crate::{
    access_control::{self, authorize_peer_service, VerifyAuthlyRole},
    access_token::VerifiedAccessToken,
    audit::Actor,
    authority_mandate::submission,
    directory,
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    util::base_uri::ProxiedBaseUri,
    AuthlyCtx,
};

/// Auth handler for admin API
pub struct AdminAuth<R: VerifyAuthlyRole> {
    user_claims: AuthlyAccessTokenClaims,
    _phantom: PhantomData<R>,
}

#[axum::async_trait]
impl<R: VerifyAuthlyRole> axum::extract::FromRequestParts<AuthlyCtx> for AdminAuth<R> {
    type Rejection = (StatusCode, &'static str);

    /// Perform the extraction.
    async fn from_request_parts(
        parts: &mut Parts,
        ctx: &AuthlyCtx,
    ) -> Result<Self, Self::Rejection> {
        let Extension(peer_svc_eid) = parts
            .extract::<Extension<PeerServiceEntity>>()
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid client"))?;

        // service requires no special privileges to call this
        let _ = authorize_peer_service(peer_svc_eid.0, &[], ctx)
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized client"))?;

        let user_token = VerifiedAccessToken::from_request_parts(parts, ctx).await?;

        if !R::verify_roles(&user_token.claims.authly.entity_attributes) {
            return Err((StatusCode::FORBIDDEN, "unprivileged user"));
        }

        Ok(Self {
            user_claims: user_token.claims,
            _phantom: PhantomData,
        })
    }
}

// FIXME: User-friendly document errors
// TODO: Handle unchanged documents like in load.rs
pub async fn post_document(
    State(ctx): State<AuthlyCtx>,
    auth: AdminAuth<access_control::role::ApplyDocument>,
    body: String,
) -> Result<Response, Response> {
    let doc = Document::from_toml(&body)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid toml").into_response())?;

    let meta = DocumentMeta {
        url: format!(
            "admin://user/?entity_id={}",
            auth.user_claims.authly.entity_id
        ),
        hash: {
            let mut hasher = blake3::Hasher::new();
            hasher.update(body.as_bytes());
            hasher.finalize().into()
        },
    };

    let compiled_doc = compile_doc(doc, meta, &ctx)
        .await
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid document").into_response())?;

    directory::apply_document(compiled_doc, &ctx)
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
    auth: AdminAuth<access_control::role::GrantMandate>,
    proxied_base_uri: ProxiedBaseUri,
) -> Result<Response, Response> {
    let token = submission::authority::authority_generate_submission_token(
        &ctx,
        proxied_base_uri.uri.to_string(),
        Actor(auth.user_claims.authly.entity_id),
        None,
    )
    .await
    .map_err(|err| {
        warn!(?err, "unable to create submission token");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    Ok(token.into_response())
}
