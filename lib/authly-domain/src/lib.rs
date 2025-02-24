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
pub mod document;
pub mod encryption;
pub mod error;
pub mod extract;
pub mod id;
pub mod instance;
pub mod login;
pub mod migration;
pub mod persona_directory;
pub mod policy;
pub mod remote_addr;
pub mod repo;
pub mod serde_util;
pub mod service;
pub mod session;
pub mod settings;
pub mod tls;

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct IsLeaderDb(pub bool);
