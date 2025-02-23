use serde::{Deserialize, Serialize};

pub mod access_control;
pub mod access_token;
pub mod audit;
pub mod builtins;
pub mod bus;
pub mod cert;
pub mod ctx;
pub mod dev;
pub mod directory;
pub mod encryption;
pub mod extract;
pub mod id;
pub mod instance;
pub mod login;
pub mod migration;
pub mod persona_directory;
pub mod repo;
pub mod session;
pub mod tls;

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct IsLeaderDb(pub bool);
