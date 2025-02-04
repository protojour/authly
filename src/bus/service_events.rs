use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use authly_common::id::Eid;
use fnv::FnvHashMap;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use super::message::ServiceMessage;

type MsgSender = tokio::sync::mpsc::Sender<ServiceMessage>;

#[derive(Clone)]
pub struct ServiceMessageConnection {
    pub sender: tokio::sync::mpsc::Sender<ServiceMessage>,
    pub addr: SocketAddr,
}

type SenderMap = FnvHashMap<Eid, Vec<ServiceMessageConnection>>;

#[derive(Clone)]
pub struct ServiceEventDispatcher {
    map: Arc<RwLock<SenderMap>>,
    cancel: CancellationToken,
}

impl ServiceEventDispatcher {
    pub fn new(cancel: CancellationToken) -> Self {
        Self {
            map: Default::default(),
            cancel,
        }
    }

    pub fn subscribe(&self, svc_eid: Eid, connection: ServiceMessageConnection) {
        self.clone()
            .spawn_watcher(svc_eid, connection.sender.clone());

        let mut map = self.map.write().unwrap();
        map.entry(svc_eid).or_default().push(connection);
    }

    /// Broadcast to all services and connections
    pub fn broadcast_all(&self, msg: ServiceMessage) {
        let stats = self.statistics();

        for (svc_eid, _) in stats {
            self.broadcast(svc_eid, msg.clone());
        }
    }

    /// Broadcast to a single service (all connections)
    pub fn broadcast(&self, svc_eid: Eid, msg: ServiceMessage) {
        let mut slow_connections: Vec<ServiceMessageConnection> = vec![];

        {
            // NB map lock is held here
            let map = self.map.read().unwrap();
            let Some(connections) = map.get(&svc_eid) else {
                return;
            };

            for connection in connections {
                let result = connection.sender.try_send(msg.clone());

                if result.is_err() {
                    slow_connections.push(connection.clone());
                }
            }
        }

        for connection in slow_connections {
            let addr = connection.addr;
            info!(
                ?svc_eid,
                ?msg,
                ?addr,
                "slow service connection; message capacity full, going to spawn a worker"
            );

            let dispatcher = self.clone();
            let msg = msg.clone();

            tokio::task::spawn(async move {
                let send_result = connection
                    .sender
                    .send_timeout(msg, Duration::from_secs(10))
                    .await;

                if let Err(err) = send_result {
                    error!(?err, ?svc_eid, ?connection.addr, "not responding, forgetting connection");

                    dispatcher.forget(svc_eid, &connection.sender);
                }
            });
        }
    }

    /// Collect connection statistics for each connected service
    pub fn statistics(&self) -> BTreeMap<Eid, usize> {
        let map = self.map.read().unwrap();
        let mut stats = BTreeMap::default();

        for (eid, senders) in map.iter() {
            stats.insert(*eid, senders.len());
        }

        stats
    }

    /// Spawn a watcher that calls `gc` when the sender's channel has been closed
    fn spawn_watcher(self, svc_eid: Eid, sender: MsgSender) {
        let sender = sender.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = sender.closed() => {
                    self.gc(svc_eid);
                }
                _ = self.cancel.cancelled() => {}
            }
        });
    }

    // Remove senders associated with closed channels
    fn gc(&self, svc_eid: Eid) {
        let mut map = self.map.write().unwrap();
        let Some(connections) = map.get_mut(&svc_eid) else {
            return;
        };

        connections.retain(|connection| {
            if connection.sender.is_closed() {
                info!(?svc_eid, ?connection.addr, "peer service hung up");
                false
            } else {
                true
            }
        });

        if connections.is_empty() {
            map.remove(&svc_eid);
        }
    }

    fn forget(&self, svc_eid: Eid, sender: &MsgSender) {
        let mut map = self.map.write().unwrap();
        let Some(connections) = map.get_mut(&svc_eid) else {
            return;
        };

        connections.retain(|connection| !connection.sender.same_channel(sender));

        if connections.is_empty() {
            map.remove(&svc_eid);
        }
    }
}
