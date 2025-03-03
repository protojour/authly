use std::{borrow::Cow, collections::BTreeMap};

use anyhow::{anyhow, Context};
use authly_domain::{
    ctx::{Directories, GetDb, GetDecryptedDeks, GetHttpClient},
    directory::{OAuthDirectory, PersonaDirectory},
    extract::base_uri::ProxiedBaseUri,
    persona_directory::{self, ForeignPersona},
    session::init_session,
};
use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use http::StatusCode;
use rand::{rngs::OsRng, Rng};
use reqwest::Url;
use tracing::warn;

#[derive(Debug)]
pub enum OAuthError {
    PersonaDirectoryNotFound,
    MissingCode,
    FetchToken(reqwest::Error),
    DeserializeToken(reqwest::Error),
    MissingAccessToken,
    FetchUser(reqwest::Error),
    DeserializeUser(reqwest::Error),
    NoUserId,
    NoUserEmail,
    AuthUrl,
    TokenUrl,
    CallbackUrl,
    EntityLink(anyhow::Error),
    Session(anyhow::Error),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> axum::response::Response {
        warn!(?self, "OAuth error");

        match self {
            Self::PersonaDirectoryNotFound => StatusCode::NOT_FOUND.into_response(),
            Self::MissingCode => StatusCode::UNPROCESSABLE_ENTITY.into_response(),
            Self::FetchToken(_) | Self::FetchUser(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            Self::DeserializeToken(_)
            | Self::MissingAccessToken
            | Self::DeserializeUser(_)
            | Self::NoUserId
            | Self::NoUserEmail => StatusCode::BAD_GATEWAY.into_response(),
            Self::AuthUrl
            | Self::TokenUrl
            | Self::CallbackUrl
            | Self::EntityLink(_)
            | Self::Session(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

pub async fn oauth_callback<Ctx>(
    State(ctx): State<Ctx>,
    base_uri: ProxiedBaseUri,
    Path(label): Path<String>,
    query: Query<BTreeMap<String, String>>,
) -> Result<Response, OAuthError>
where
    Ctx: GetDb + Directories + GetHttpClient + GetDecryptedDeks,
{
    let persona_directories = ctx.load_persona_directories();
    let Some(PersonaDirectory::OAuth(oauth)) = persona_directories.get(&label) else {
        return Err(OAuthError::PersonaDirectoryNotFound);
    };

    let client = ctx.get_internet_http_client();

    let mut token_response: BTreeMap<String, String> = client
        .post(build_oauth_token_url(query, &label, oauth, &base_uri)?)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(OAuthError::FetchToken)?
        .error_for_status()
        .map_err(OAuthError::FetchToken)?
        .json()
        .await
        .map_err(OAuthError::DeserializeToken)?;

    let access_token = oauth
        .token_res_access_token_field
        .as_deref()
        .and_then(|field| token_response.remove(field))
        .ok_or(OAuthError::MissingAccessToken)?;

    let user_response: serde_json::Value = client
        .get(&oauth.user_url)
        .header("authorization", format!("Bearer {access_token}"))
        .header("accept", "application/json")
        .send()
        .await
        .map_err(OAuthError::FetchUser)?
        .error_for_status()
        .map_err(OAuthError::FetchUser)?
        .json()
        .await
        .map_err(OAuthError::DeserializeUser)?;

    let user_id = json_str_by_path_opt(&user_response, oauth.user_res_id_path.as_deref())
        .ok_or(OAuthError::NoUserId)?
        .map_err(|_| OAuthError::NoUserId)?;
    let email = json_str_by_path_opt(&user_response, oauth.user_res_email_path.as_deref())
        .ok_or(OAuthError::NoUserEmail)?
        .map_err(|_| OAuthError::NoUserEmail)?;

    let (persona_id, _) = persona_directory::link_foreign_persona(
        &ctx,
        oauth.dir_key,
        ForeignPersona {
            foreign_id: user_id.as_ref().as_bytes().to_vec(),
            email: email.to_string(),
        },
    )
    .await
    .map_err(|err| OAuthError::EntityLink(err.into()))?;

    let session = init_session(&ctx, persona_id.upcast())
        .await
        .map_err(|err| OAuthError::Session(err.into()))?;

    Ok(CookieJar::new().add(session.to_cookie()).into_response())
}

/// Build the URL to the external OAuth login website
pub fn build_oauth_web_authorize_url(
    oauth: &OAuthDirectory,
    label: &str,
    base_uri: &ProxiedBaseUri,
) -> Result<String, OAuthError> {
    let mut url = Url::parse(&oauth.auth_url).map_err(|_| OAuthError::AuthUrl)?;

    {
        let mut q = url.query_pairs_mut();

        if let Some(field) = oauth.auth_req_client_id_field.as_deref() {
            q.append_pair(field, &oauth.client_id);
        }

        if let Some(field) = oauth.auth_req_nonce_field.as_deref() {
            let mut nonce = [0u8; 32];
            OsRng.fill(nonce.as_mut_slice());

            q.append_pair(field, &hexhex::hex(nonce).to_string());
        }

        // This is optional but recommended for github, but there is no state for not sending this in the DB
        if let Some(field) = oauth.token_req_callback_url_field.as_deref() {
            q.append_pair(field, &build_authly_oauth_callback_url(label, base_uri)?);
        }
    }

    Ok(url.to_string())
}

// Build the URL pointing to where the external app will redirect back to Authly
fn build_authly_oauth_callback_url(
    label: &str,
    base_uri: &ProxiedBaseUri,
) -> Result<String, OAuthError> {
    let mut url = Url::parse(&base_uri.0.to_string()).map_err(|_| OAuthError::CallbackUrl)?;
    url.path_segments_mut()
        .map_err(|_| OAuthError::CallbackUrl)?
        .extend(["auth", "oauth", label, "callback"]);

    Ok(url.as_str().to_string())
}

/// Build the URL to the web API where the access token can be requested
fn build_oauth_token_url(
    mut query: Query<BTreeMap<String, String>>,
    label: &str,
    oauth: &OAuthDirectory,
    base_uri: &ProxiedBaseUri,
) -> Result<String, OAuthError> {
    let mut url = Url::parse(&oauth.token_url).map_err(|_| OAuthError::TokenUrl)?;

    {
        let mut q = url.query_pairs_mut();

        if let Some(field) = oauth.token_req_client_id_field.as_deref() {
            q.append_pair(field, &oauth.client_id);
        }
        if let Some(field) = oauth.token_req_client_secret_field.as_deref() {
            q.append_pair(field, &oauth.client_secret);
        }

        if let (Some(input), Some(output)) = (
            oauth.auth_res_code_path.as_deref(),
            oauth.token_req_code_field.as_deref(),
        ) {
            let code = query.remove(input).ok_or(OAuthError::MissingCode)?;
            q.append_pair(output, &code);
        }

        if let Some(field) = oauth.token_req_callback_url_field.as_deref() {
            q.append_pair(field, &build_authly_oauth_callback_url(label, base_uri)?);
        }
    }

    Ok(url.to_string())
}

fn json_str_by_path_opt<'j>(
    json: &'j serde_json::Value,
    path: Option<&str>,
) -> Option<anyhow::Result<Cow<'j, str>>> {
    match path.map(|path| json_by_path(json, path))? {
        Ok(value) => match value {
            serde_json::Value::Number(number) => Some(Ok(Cow::Owned(number.to_string()))),
            serde_json::Value::String(string) => Some(Ok(Cow::Borrowed(string))),
            _ => Some(Err(anyhow!("expected number or string"))),
        },
        Err(err) => Some(Err(err)),
    }
}

#[expect(unused)]
fn json_by_path_opt<'j>(
    json: &'j serde_json::Value,
    path: Option<&str>,
) -> Option<anyhow::Result<&'j serde_json::Value>> {
    path.map(|path| json_by_path(json, path))
}

fn json_by_path<'j>(
    json: &'j serde_json::Value,
    path: &str,
) -> anyhow::Result<&'j serde_json::Value> {
    match path.split_once(".") {
        Some((key, rest)) => {
            if let serde_json::Value::Object(obj) = json {
                let value = obj.get(key).context("no such key")?;
                json_by_path(value, rest)
            } else {
                Err(anyhow!("expected object"))
            }
        }
        None => {
            if let serde_json::Value::Object(obj) = json {
                Ok(obj.get(path).context("no such key")?)
            } else {
                Err(anyhow!("expected object"))
            }
        }
    }
}
