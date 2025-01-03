use authly_proto::service as proto;
use authly_proto::service::authly_service_client::AuthlyServiceClient;
use reqwest::ClientBuilder;
use serde_json::{json, Value};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use tracing::info;

struct ServiceClient {
    client: AuthlyServiceClient<tonic::transport::Channel>,
}

async fn testservice_grpc_client() -> anyhow::Result<AuthlyServiceClient<tonic::transport::Channel>>
{
    let mut identity_pems =
        pem::parse_many(std::fs::read("../../test/testservice-identity.pem")?)?.into_iter();

    let mut tls_config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&std::fs::read(
            "../../test/exported-local-ca.pem",
        )?))
        .identity(Identity::from_pem(
            pem::encode(&identity_pems.next().unwrap()),
            pem::encode(&identity_pems.next().unwrap()),
        ));

    let mut endpoint = tonic::transport::Endpoint::from_shared("https://localhost:10443")?
        .tls_config(tls_config)?;

    Ok(AuthlyServiceClient::new(endpoint.connect().await?))
}

#[tokio::test]
async fn test_metadata() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut client = testservice_grpc_client().await?;

    let service_metadata = client.metadata(proto::Empty::default()).await?.into_inner();

    assert_eq!(service_metadata.name, "testservice");

    Ok(())
}
