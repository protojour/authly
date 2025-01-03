#![allow(unused)]

use reqwest::{ClientBuilder, Identity};
use serde_json::{json, Value};
use tracing::info;

fn testservice_client() -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::tls::Certificate::from_pem(&std::fs::read(
            "../../test/exported-local-ca.pem",
        )?)?)
        .identity(Identity::from_pem(&std::fs::read(
            "../../test/testservice-identity.pem",
        )?)?)
        .build()?;

    Ok(client)
}

#[tokio::test]
async fn user_auth() -> anyhow::Result<()> {
    let client = testservice_client().unwrap();

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
