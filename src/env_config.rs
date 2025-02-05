use std::{net::SocketAddr, path::PathBuf};

use figment::{
    providers::{Env, Serialized},
    Figment,
};
use serde::{Deserialize, Serialize};

use crate::util::serde::Hex;

/// Configuration values always read from the environment.
///
/// These values are closely tied to the platform Authly runs on,
/// and are not runtime-configurable.
#[derive(Serialize, Deserialize, Debug)]
pub struct EnvConfig {
    /// A unique identifier for this Authly instance.
    /// It should be fairly unique, should never change, and is not particularly secret.
    /// Global uniqueness is not required, but a form of local uniqueness is required
    /// in closed systems running several authly instances.
    pub id: Hex<[u8; 32]>,

    /// The hostname against which to generate server certificates
    pub hostname: String,

    /// The port on which to run the API/web server
    pub server_port: u16,

    /// A list of paths to scan for documents during startup.
    pub document_path: Vec<PathBuf>,

    /// Configuration directory
    pub etc_dir: PathBuf,

    /// Database directory
    pub data_dir: PathBuf,

    /// OpenBao URL for master encryption key storage
    pub bao_url: Option<String>,

    /// OpenBao token support for legacy setups
    pub bao_token: Option<String>,

    pub cluster_node_id: Option<u64>,
    pub cluster_api_nodes: Option<Vec<SocketAddr>>,
    pub cluster_raft_nodes: Option<Vec<SocketAddr>>,
    pub cluster_raft_secret: String,
    pub cluster_api_secret: String,

    pub k8s: bool,
    pub k8s_statefulset: Option<String>,
    pub k8s_headless_svc: String,
    pub k8s_replicas: u64,
    pub k8s_auth_hostname: Option<String>,
    pub k8s_auth_server_port: Option<u16>,

    /// Whether to export certificates and identities to AUTHLY_ETC_DIR
    pub export_tls_to_etc: bool,

    /// A plain http (no https) debug port for serving /web/ endpoints, intended for development.
    #[cfg(feature = "dev")]
    pub debug_web_port: Option<u16>,
}

const NULL_ID: [u8; 32] = [0; 32];

impl EnvConfig {
    pub fn load() -> Self {
        let cfg: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("AUTHLY_"))
            .extract()
            .unwrap();

        if cfg.id.0 == NULL_ID {
            panic!("AUTHLY_ID not specified");
        }

        cfg
    }

    pub fn cluster_tls_path(&self) -> ClusterTlsPath {
        ClusterTlsPath(self.etc_dir.join("cluster"))
    }
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            id: Hex(NULL_ID),

            hostname: "authly".to_string(),
            server_port: 443,

            document_path: vec![PathBuf::from("/etc/authly/documents")],

            etc_dir: PathBuf::from("/etc/authly"),
            data_dir: PathBuf::from("/var/lib/authly/data"),

            bao_url: None,
            bao_token: None,

            cluster_node_id: None,
            cluster_raft_nodes: None,
            cluster_api_nodes: None,
            cluster_raft_secret: "superultramegasecret1".to_string(),
            cluster_api_secret: "superultramegasecret2".to_string(),

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
