use std::path::PathBuf;

use figment::{
    providers::{Env, Serialized},
    Figment,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthlyConfig {
    pub data_dir: PathBuf,

    pub cert_file: PathBuf,
    pub key_file: PathBuf,

    pub raft_secret: String,
    pub api_secret: String,
}

impl AuthlyConfig {
    pub fn load() -> Self {
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("AUTHLY"))
            .extract()
            .unwrap()
    }
}

impl Default for AuthlyConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/authly"),
            cert_file: PathBuf::from("./certs/server.pem"),
            key_file: PathBuf::from("./certs/server.key"),

            raft_secret: "superultramegasecret1".to_string(),
            api_secret: "superultramegasecret2".to_string(),
        }
    }
}
