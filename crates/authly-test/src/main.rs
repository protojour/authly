use serde_json::{json, Value};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    let client = reqwest::Client::builder()
        // TODO: is it possible to accept a localhost cert?
        .danger_accept_invalid_certs(true)
        .add_root_certificate(reqwest::tls::Certificate::from_pem(
            std::fs::read_to_string("./test/root-ca.pem")?.as_bytes(),
        )?)
        .build()?;

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
