use std::time::Duration;

use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    info!("HELLO");

    let client = authly_client::Client::builder()
        .from_environment()
        .await
        .unwrap()
        .connect()
        .await
        .unwrap();

    let eid = client.eid().await.unwrap();
    let label = client.label().await.unwrap();

    info!("client running, eid={eid} label={label}");

    tokio::time::sleep(Duration::from_secs(1000000000000)).await;
}
