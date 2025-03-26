use std::{fmt::Display, str::FromStr};

use axum::RequestPartsExt;
use http::{
    request::Parts,
    uri::{self, Authority, PathAndQuery, Scheme},
    HeaderMap, Uri,
};

use crate::dev::IsDev;

/// An extractor that tries to guess the public Uri based on proxy headers
#[derive(Default)]
pub struct ProxiedUri(pub Uri);

impl Display for ProxiedUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<S: Sync> axum::extract::FromRequestParts<S> for ProxiedUri {
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let mut uri_parts = parts.uri.clone().into_parts();
        adjust_uri_proxy_parts(&mut uri_parts, &parts.headers)?;
        Ok(Self(Uri::from_parts(uri_parts).map_err(|_| ())?))
    }
}

/// An extractor that tries to guess the public Uri based on proxy headers
///
/// This version removes the authly-internal path.
#[derive(Default)]
pub struct ProxiedBaseUri(pub Uri);

impl Display for ProxiedBaseUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<S: Sync> axum::extract::FromRequestParts<S> for ProxiedBaseUri {
    type Rejection = ();

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let mut uri_parts = parts.uri.clone().into_parts();

        // since the _base_ URI is what's desired, clear the path:
        uri_parts.path_and_query = None;

        if parts.extract::<IsDev>().await.unwrap_or(IsDev(false)).0 {
            // dev mode
            uri_parts.scheme = Some(Scheme::HTTP);
            uri_parts.authority = Some(Authority::from_maybe_shared("localhost:12345").unwrap());
            uri_parts.path_and_query = Some("/".parse().unwrap());
        } else {
            adjust_uri_proxy_parts(&mut uri_parts, &parts.headers)?;
        }

        Ok(Self(Uri::from_parts(uri_parts).map_err(|err| {
            tracing::error!(?err, "proxied base uri")
        })?))
    }
}

#[derive(Default)]
pub struct ForwardedPrefix(pub String);

impl<S: Sync> axum::extract::FromRequestParts<S> for ForwardedPrefix {
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

fn adjust_uri_proxy_parts(uri_parts: &mut uri::Parts, headers: &HeaderMap) -> Result<(), ()> {
    if let Some(proto) = headers.get("x-forwarded-proto") {
        if let Ok(proto) = proto.to_str() {
            uri_parts.scheme = Some(Scheme::try_from(proto).map_err(|_| ())?);
        };
    }

    {
        let mut host = uri_parts.authority.as_ref().map(|a| a.host().to_string());
        let mut port = uri_parts
            .authority
            .as_ref()
            .and_then(Authority::port)
            .map(|p| p.to_string());

        if let Some(xfhost) = headers.get("x-forwarded-host") {
            host = xfhost.to_str().ok().map(ToString::to_string);
        }

        if let Some(xfport) = headers.get("x-forwarded-port") {
            port = xfport.to_str().ok().map(ToString::to_string);
        }

        if host.is_some() || port.is_some() {
            let mut auth = host.unwrap_or_default();
            if let Some(port) = port {
                auth.push(':');
                auth.push_str(&port);
            }

            uri_parts.authority = Some(Authority::from_str(&auth).map_err(|_| ())?);
        }
    }

    if let Some(prefix) = headers.get("x-forwarded-prefix") {
        if let Ok(prefix) = prefix.to_str() {
            let mut new_pq = prefix.to_string();

            if let Some(pq) = uri_parts.path_and_query.take() {
                new_pq.push_str(pq.path());

                if let Some(query) = pq.query() {
                    new_pq.push('?');
                    new_pq.push_str(query);
                }
            }

            uri_parts.path_and_query = Some(PathAndQuery::from_str(&new_pq).map_err(|_| ())?);
        };
    }

    Ok(())
}
