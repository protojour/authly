use std::env;

use authly::{run_authly, test_node_config};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    let data_dir = env::var("AUTHLY_DATA_DIR").unwrap_or_else(|_| "/var/lib/authly".to_string());
    let node_config = test_node_config(&data_dir);

    run_authly(node_config).await
}
