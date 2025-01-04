use std::{net::SocketAddr, path::PathBuf};

use figment::{
    providers::{Env, Serialized},
    Figment,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EnvConfig {
    pub hostname: String,
    pub data_dir: PathBuf,

    pub node_id: Option<u64>,

    pub cluster_cert_file: PathBuf,
    pub cluster_key_file: PathBuf,
    pub cluster_raft_secret: String,
    pub cluster_api_secret: String,

    pub k8s: bool,
    pub k8s_statefulset: Option<String>,
    pub k8s_headless_svc: Option<String>,
    pub k8s_replicas: Option<u64>,
    pub k8s_auth_hostname: Option<String>,
    pub k8s_auth_server_port: Option<u16>,

    pub cluster_api_nodes: Option<Vec<SocketAddr>>,
    pub cluster_raft_nodes: Option<Vec<SocketAddr>>,

    pub export_local_ca: Option<PathBuf>,
}

impl EnvConfig {
    pub fn load() -> Self {
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("AUTHLY_"))
            .extract()
            .unwrap()
    }
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            hostname: "authly-local".to_string(),
            data_dir: PathBuf::from("/var/lib/authly/data"),
            node_id: None,

            export_local_ca: None,

            cluster_cert_file: PathBuf::from("/etc/authly/cluster/tls.crt"),
            cluster_key_file: PathBuf::from("/etc/authly/cluster/tls.key"),

            cluster_raft_secret: "superultramegasecret1".to_string(),
            cluster_api_secret: "superultramegasecret2".to_string(),

            cluster_raft_nodes: None,
            cluster_api_nodes: None,

            k8s: false,
            k8s_statefulset: None,
            k8s_headless_svc: None,
            k8s_replicas: None,
            k8s_auth_hostname: None,
            k8s_auth_server_port: None,
        }
    }
}
