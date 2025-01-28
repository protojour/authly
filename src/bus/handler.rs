use tracing::info;

use crate::{
    ctx::{Broadcast, GetDb, GetDecryptedDeks, RedistributeCertificates, SetInstance},
    db::cryptography_db::load_authly_instance,
    IsLeaderDb,
};

use super::message::{ClientMessage, ClusterMessage};

/// Handle incoming message from the cluster notify mechanism
pub async fn authly_node_handle_incoming_message(
    deps: &(impl GetDb + GetDecryptedDeks + SetInstance + RedistributeCertificates + Broadcast),
    message: ClusterMessage,
) -> anyhow::Result<()> {
    // Step 1: central processing
    match message {
        ClusterMessage::InstanceChanged => {
            // step 1: re-load instance
            // IsLeaderDb is not important when not starting up the first time
            let deks = deps.load_decrypted_deks();
            let new_instance = load_authly_instance(IsLeaderDb(true), deps.get_db(), &deks).await?;
            deps.set_instance(new_instance);

            // step 2: make sure new certificates are redistributed.
            // only the leader node needs to do this.
            deps.redistribute_certificates_if_leader().await;

            // step 3: if leader, send message to other cluster nodes to reset their connected clients.
            deps.broadcast_to_cluster_if_leader(ClusterMessage::ClientBroadcast(
                ClientMessage::Reset,
            ))
            .await?;
        }
        ClusterMessage::DirectoryChanged { did } => {
            info!(?did, "directory changed");
        }
        ClusterMessage::ClientBroadcast(client_message) => {
            info!(?client_message, "TODO: client broadcast");
        }
        ClusterMessage::Ping => {}
    }

    Ok(())
}
