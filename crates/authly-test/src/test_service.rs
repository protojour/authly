use authly_client::{identity::Identity, Client};
use reqwest::ClientBuilder;
use serde_json::{json, Value};
use tracing::info;

async fn client() -> anyhow::Result<Client> {
    Ok(Client::builder()
        .with_url("https://localhost:10443")
        .with_authly_local_ca_pem(std::fs::read("../../test/exported-local-ca.pem")?)
        .with_identity(authly_client::identity::Identity::from_multi_pem(
            std::fs::read("../../test/testservice-identity.pem")?,
        )?)
        .connect()
        .await?)
}

#[tokio::test]
async fn test_metadata() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut client = client().await?;

    let name = client.name().await?;

    assert_eq!(name, "testservice");

    Ok(())
}
