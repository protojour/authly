use anyhow::Context;
use tracing::info;

use crate::{
    bus::{ClusterMessage, ServiceMessage},
    ctx::{ClusterBus, GetDb, GetDecryptedDeks, RedistributeCertificates, ServiceBus, SetInstance},
    repo::{
        crypto_repo::load_authly_instance,
        directory_repo::{query_dir_key, DbDirectoryService},
    },
    IsLeaderDb,
};

/// Handle incoming message from the cluster notify mechanism
pub async fn authly_node_handle_incoming_message(
    deps: &(impl GetDb
          + GetDecryptedDeks
          + SetInstance
          + RedistributeCertificates
          + ClusterBus
          + ServiceBus),
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
            deps.broadcast_to_cluster_if_leader(ClusterMessage::ServiceBroadcast(
                ServiceMessage::ReloadCa,
            ))
            .await?;
        }
        ClusterMessage::DirectoryChanged { dir_id } => {
            info!(?dir_id, "directory changed");
            let dir_key = query_dir_key(deps.get_db(), dir_id)
                .await?
                .context("no such directory")?;

            for service in DbDirectoryService::query(deps.get_db(), dir_key).await? {
                deps.service_event_dispatcher()
                    .broadcast(service.svc_eid, ServiceMessage::ReloadCache);
            }
        }
        ClusterMessage::ServiceBroadcast(message) => {
            info!(?message, "service broadcast");

            deps.service_event_dispatcher().broadcast_all(message);
        }
        ClusterMessage::ClusterPing => {
            info!(?message, "TODO: handle cluster ping");
        }
    }

    Ok(())
}
