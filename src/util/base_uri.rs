use std::{fmt::Display, str::FromStr};

use http::{
    request::Parts,
    uri::{Authority, PathAndQuery, Scheme},
    Uri,
};

/// An extractor that tries to guess the public Uri based on proxy headers
#[derive(Default)]
pub struct ProxiedBaseUri(pub Uri);

impl Display for ProxiedBaseUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ProxiedBaseUri {
    fn from_parts(parts: &mut Parts) -> Result<Self, ()> {
        let mut uri_parts = parts.uri.clone().into_parts();

        // since the _base_ URI is what's desired, clear the path:
        uri_parts.path_and_query = None;

        if let Some(proto) = parts.headers.get("x-forwarded-proto") {
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

            if let Some(xfhost) = parts.headers.get("x-forwarded-host") {
                host = xfhost.to_str().ok().map(ToString::to_string);
            }

            if let Some(xfport) = parts.headers.get("x-forwarded-port") {
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

        if let Some(prefix) = parts.headers.get("x-forwarded-prefix") {
            if let Ok(prefix) = prefix.to_str() {
                uri_parts.path_and_query = Some(PathAndQuery::from_str(prefix).map_err(|_| ())?);
            };
        }

        Ok(Self(Uri::from_parts(uri_parts).map_err(|_| ())?))
    }
}

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for ProxiedBaseUri {
    type Rejection = ();

    /// Perform the extraction.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Self::from_parts(parts)
    }
}
