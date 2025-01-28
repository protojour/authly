use tokio::sync::broadcast;

pub mod cluster;
pub mod handler;
pub mod message;

#[derive(thiserror::Error, Debug)]
pub enum BusError {
    #[error("hiqlite notify error: {0}")]
    HqlNotify(hiqlite::Error),

    #[error("bus receive error: {0}")]
    Receive(broadcast::error::RecvError),
}
