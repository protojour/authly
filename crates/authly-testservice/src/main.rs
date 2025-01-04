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

    let client = authly_client::Client::infer().await.unwrap();

    let eid = client.eid().await.unwrap();
    let name = client.name().await.unwrap();

    info!("client running, eid={eid} name={name}");

    tokio::time::sleep(Duration::from_secs(1000000000000)).await;
}
