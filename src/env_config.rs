use std::{net::SocketAddr, path::PathBuf};

use figment::{
    providers::{Env, Serialized},
    Figment,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EnvConfig {
    /// The hostname against which to generate server certificates
    pub hostname: String,

    /// A list of paths to scan for documents during startup.
    pub document_path: Vec<PathBuf>,

    /// Configuration directory
    pub etc_dir: PathBuf,

    /// Database directory
    pub data_dir: PathBuf,

    pub node_id: Option<u64>,

    pub cluster_raft_secret: String,
    pub cluster_api_secret: String,

    pub k8s: bool,
    pub k8s_statefulset: Option<String>,
    pub k8s_headless_svc: String,
    pub k8s_replicas: u64,
    pub k8s_auth_hostname: Option<String>,
    pub k8s_auth_server_port: Option<u16>,

    pub cluster_api_nodes: Option<Vec<SocketAddr>>,
    pub cluster_raft_nodes: Option<Vec<SocketAddr>>,

    /// Whether to export certificates and identities to AUTHLY_ETC_DIR
    pub export_tls_to_etc: bool,

    /// A plain http (no https) debug port for serving /web/ endpoints, intended for development.
    #[cfg(feature = "dev")]
    pub debug_web_port: Option<u16>,
}

impl EnvConfig {
    pub fn load() -> Self {
        Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("AUTHLY_"))
            .extract()
            .unwrap()
    }

    pub fn cluster_tls_path(&self) -> ClusterTlsPath {
        ClusterTlsPath(self.etc_dir.join("cluster"))
    }
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            hostname: "authly".to_string(),

            document_path: vec![PathBuf::from("/etc/authly/documents")],

            etc_dir: PathBuf::from("/etc/authly"),
            data_dir: PathBuf::from("/var/lib/authly/data"),
            node_id: None,

            cluster_raft_secret: "superultramegasecret1".to_string(),
            cluster_api_secret: "superultramegasecret2".to_string(),

            cluster_raft_nodes: None,
            cluster_api_nodes: None,

            k8s: false,
            k8s_statefulset: Some("authly".to_string()),
            k8s_headless_svc: "authly-cluster".to_string(),
            k8s_replicas: 1,
            k8s_auth_hostname: None,
            k8s_auth_server_port: None,

            export_tls_to_etc: false,

            #[cfg(feature = "dev")]
            debug_web_port: None,
        }
    }
}

pub struct ClusterTlsPath(pub PathBuf);

impl ClusterTlsPath {
    pub fn key_path(&self) -> PathBuf {
        self.0.join("tls.key")
    }

    pub fn cert_path(&self) -> PathBuf {
        self.0.join("tls.crt")
    }
}
