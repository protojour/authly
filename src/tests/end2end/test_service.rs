use super::ConnectionBuilder;

#[tokio::test]
#[ignore = "end2end"]
async fn test_metadata() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = ConnectionBuilder::for_testservice()?
        .service_client()
        .await?;

    let metadata = client.metadata().await?;
    assert_eq!(metadata.label(), "testservice");

    Ok(())
}
