use authly_common::id::DirectoryId;
use serde::{Deserialize, Serialize};

/// Message type used by the Authly message bus (hiqlite notify mechanism).
///
/// The message bus is a broadcast bus and every message will be sent to all nodes in the cluster.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ClusterMessage {
    /// The AuthlyInstance has been rewritten in the database.
    /// This should trigger:
    /// 1. Re-load of AuthlyInstance
    /// 2. Certificate redistribution
    /// 3. Notify all connected clients
    InstanceChanged,

    /// An directory caused a change to the database.
    /// It can also mean the directory was added or removed.
    DirectoryChanged {
        /// The directory ID that changed
        dir_id: DirectoryId,
    },

    /// Broadcast message to all connected service instances
    ServiceBroadcast(ServiceMessage),

    /// This message does not mean anything, a healthcheck module can send this message
    /// to "itself" and check whether it's received again.
    ClusterPing,
}

/// This will turn into a gRPC message broadcasted to connected services.
///
/// The message is sometimes associated with a specific service Eid (and its connections),
/// the messages can also be broadcasted to _all_ connected services.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ServiceMessage {
    /// A message to tell clients to reset everything and reconnect to Authly.
    /// This includes re-loading certificates.
    ReloadCa,

    /// Reload local caches
    ReloadCache,

    /// Send the Ping message to service instances
    Ping,
}

#[test]
fn directory_changed_serde() {
    let msg0 = ClusterMessage::DirectoryChanged {
        dir_id: DirectoryId::random(),
    };
    let json = serde_json::to_vec(&msg0).unwrap();
    let msg1: ClusterMessage = serde_json::from_slice(&json).unwrap();

    assert_eq!(msg0, msg1);
}
