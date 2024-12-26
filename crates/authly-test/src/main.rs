use reqwest::Client;
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

    let client = Client::new();

    let response: Value = client
        .post("http://localhost:8888/auth/authenticate")
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

    info!(?response, "authenticated");

    Ok(())
}
