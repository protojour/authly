use authly_client::{identity::Identity, Client};
use reqwest::ClientBuilder;
use serde_json::{json, Value};
use tracing::info;

use crate::testservice_authly_client;

#[tokio::test]
async fn test_metadata() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut client = testservice_authly_client().await?;

    let label = client.label().await?;

    assert_eq!(label, "testservice");

    Ok(())
}
