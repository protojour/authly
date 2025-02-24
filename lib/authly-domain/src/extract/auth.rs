use std::marker::PhantomData;

use anyhow::anyhow;
use authly_common::{access_token::AuthlyAccessTokenClaims, mtls_server::PeerServiceEntity};
use axum::{extract::FromRequestParts, response::IntoResponse, Extension, RequestPartsExt};
use http::{
    header::{self, LOCATION},
    request::Parts,
    HeaderName, HeaderValue, StatusCode,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

use crate::{
    access_control::{authorize_peer_service, VerifyAuthlyRole},
    access_token::{create_access_token_claims, VerifiedAccessToken},
    ctx::{GetDb, GetInstance},
    dev::IsDev,
    repo::entity_repo,
    session::authenticate_session_cookie,
};

use super::base_uri::{ForwardedPrefix, ProxiedUri};

/// Auth handler for web APIs
pub struct ApiAuth<R: VerifyAuthlyRole> {
    pub claims: AuthlyAccessTokenClaims,
    _phantom: PhantomData<R>,
}

/// Auth handler for websites.
/// A rejection will redirect to the auth webapp.
pub struct WebAuth<R: VerifyAuthlyRole> {
    #[allow(unused)]
    pub claims: AuthlyAccessTokenClaims,
    _phantom: PhantomData<R>,
}

#[axum::async_trait]
impl<Ctx, R: VerifyAuthlyRole> axum::extract::FromRequestParts<Ctx> for ApiAuth<R>
where
    Ctx: GetDb + GetInstance + Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, ctx: &Ctx) -> Result<Self, Self::Rejection> {
        verify::<R>(parts, ctx).await.map(|claims| Self {
            claims,
            _phantom: PhantomData,
        })
    }
}

#[axum::async_trait]
impl<Ctx, R: VerifyAuthlyRole> axum::extract::FromRequestParts<Ctx> for WebAuth<R>
where
    Ctx: GetDb + GetInstance + Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request_parts(parts: &mut Parts, ctx: &Ctx) -> Result<Self, Self::Rejection> {
        match verify::<R>(parts, ctx).await {
            Ok(claims) => Ok(Self {
                claims,
                _phantom: PhantomData,
            }),
            Err((status, msg)) => match status {
                StatusCode::UNAUTHORIZED => {
                    tracing::info!(msg, "unauthorized, redirecting");
                    Err(redirect_to_login(parts).await.map_err(|err| {
                        tracing::error!(?err, "redirect");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    })?)
                }
                _ => Err((status, msg).into_response()),
            },
        }
    }
}

async fn verify<R: VerifyAuthlyRole>(
    parts: &mut Parts,
    ctx: &(impl GetDb + GetInstance + Send + Sync),
) -> Result<AuthlyAccessTokenClaims, (StatusCode, &'static str)> {
    let Extension(peer_svc_eid) = parts
        .extract::<Extension<PeerServiceEntity>>()
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid client"))?;

    let claims = if parts.extract::<IsDev>().await.unwrap_or(IsDev(false)).0 {
        // dev mode: accept session cookie directly

        let jar = cookie_jar(&parts.headers);
        let session_cookie = jar
            .get("session-cookie")
            .ok_or((StatusCode::UNAUTHORIZED, "no session cookie (dev mode)"))?;
        let session = authenticate_session_cookie(ctx, session_cookie)
            .await
            .map_err(|err| (StatusCode::UNAUTHORIZED, err))?;
        let user_attributes = entity_repo::list_entity_attrs(ctx.get_db(), session.eid)
            .await
            .map_err(|_err| (StatusCode::UNAUTHORIZED, "db error"))?;

        create_access_token_claims(&session, user_attributes)
    } else {
        // production mode

        // service requires no special privileges to call this
        let _ = authorize_peer_service(ctx, peer_svc_eid.0, &[])
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized client"))?;

        VerifiedAccessToken::from_request_parts(parts, ctx)
            .await?
            .claims
    };

    if !R::verify_roles(&claims.authly.entity_attributes) {
        return Err((StatusCode::FORBIDDEN, "unprivileged user"));
    }

    Ok(claims)
}

async fn redirect_to_login(parts: &mut Parts) -> anyhow::Result<axum::response::Response> {
    let ForwardedPrefix(prefix) = ForwardedPrefix::from_request_parts(parts, &())
        .await
        .map_err(|_| anyhow!("no prefix"))?;

    let next_uri = ProxiedUri::from_request_parts(parts, &())
        .await
        .map_err(|_| anyhow!("unable to extract proxied uri"))?
        .0
        .to_string();
    let next_uri = utf8_percent_encode(&next_uri, NON_ALPHANUMERIC);

    let auth_location = HeaderValue::from_str(&format!("{prefix}/auth?next={next_uri}"))?;

    if parts.headers.contains_key("hx-request") {
        // do a HTMX full-page redirect
        Ok((
            StatusCode::FOUND,
            [(HeaderName::from_static("hx-redirect"), auth_location)],
        )
            .into_response())
    } else {
        Ok((StatusCode::FOUND, [(LOCATION, auth_location)]).into_response())
    }
}

fn cookie_jar(headers: &http::HeaderMap) -> cookie::CookieJar {
    let cookies = headers
        .get_all(header::COOKIE)
        .into_iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie::Cookie::parse(cookie.to_owned()).ok());

    let mut jar = cookie::CookieJar::new();
    for cookie in cookies {
        jar.add_original(cookie);
    }

    jar
}
