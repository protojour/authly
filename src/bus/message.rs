use authly_common::id::Eid;
use serde::{Deserialize, Serialize};

/// Message type used by the Authly message bus (hiqlite notify mechanism).
///
/// The message bus is a broadcast bus and every message will be sent to all nodes in the cluster.
#[derive(Clone, Serialize, Deserialize, Debug)]
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
        did: Eid,
    },

    /// Broadcast message to all connected clients
    ClientBroadcast(ClientMessage),

    /// This message does not mean anything, a healthcheck module can send this message
    /// and check whether it's received.
    Ping,
}

/// This will turn into a gRPC message broadcasted to all connected clients.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ClientMessage {
    /// A message to tell clients to reset everything and reconnect to Authly.
    /// This includes re-loading certificates.
    Reset,
}
