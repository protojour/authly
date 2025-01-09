#![allow(unused)]

use authly_domain::Eid;
use cookie::Cookie;
use hyper::header::SET_COOKIE;
use reqwest::{ClientBuilder, Identity};
use serde_json::{json, Value};
use tracing::info;

use crate::{testservice_authly_client, testservice_web_client};

#[tokio::test]
async fn user_auth_ok() -> anyhow::Result<()> {
    let web_client = testservice_web_client().unwrap();

    let response: Value = web_client
        .post("https://localhost:10443/api/auth/authenticate")
        .json(&json!({
            "username": "testuser",
            "password": "secret",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    info!(?response, "user authenticated");
    Ok(())
}

#[tokio::test]
async fn auth_session_cookie_to_access_token() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let web_client = testservice_web_client().unwrap();
    let authly_client = testservice_authly_client().await.unwrap();

    let response = web_client
        .post("https://localhost:10443/api/auth/authenticate")
        .json(&json!({
            "username": "testuser",
            "password": "secret",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let mut session_cookie = Cookie::parse_encoded(
        response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();

    let access_token = authly_client
        .get_access_token(session_cookie.value_trimmed())
        .await
        .unwrap();

    assert_eq!(access_token.claims.authly.user_eid, Eid(111111));

    Ok(())
}
