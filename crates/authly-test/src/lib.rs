#![allow(unused)]

use reqwest::ClientBuilder;
use serde_json::{json, Value};
use tracing::info;

const ROOT_CA: &[u8] = include_bytes!("../../../test/root-ca.pem");

fn test_client() -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        // TODO: is it possible to accept a localhost cert?
        .danger_accept_invalid_certs(true)
        .add_root_certificate(reqwest::tls::Certificate::from_pem(ROOT_CA)?)
        .build()?;

    Ok(client)
}

#[tokio::test]
async fn user_auth() -> anyhow::Result<()> {
    let client = test_client().unwrap();

    let response: Value = client
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
async fn service_auth() -> anyhow::Result<()> {
    let client = test_client().unwrap();

    let response: Value = client
        .post("https://localhost:10443/api/auth/authenticate")
        .json(&json!({
            "serviceName": "testservice",
            "serviceSecret": "secret",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    info!(?response, "service authenticated");

    Ok(())
}
