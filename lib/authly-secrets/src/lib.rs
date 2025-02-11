use async_trait::async_trait;
use bao::BaoBackend;

mod bao;

/// A secret. Currently all secrets are 256 bit.
pub struct Secret(pub [u8; 32]);

pub struct Version(pub Vec<u8>);

/// Authly secrets backend
/// For now it only supports "versioned" APIs.
///
/// The Authly cluster must be up before generating any secrets.
/// The reason is that secrets can't be atomically generated.
/// The cluster first needs to elect a leader and only the leader may generate secrets while the other nodes wait.
/// If not done this way, there is no guarantee that the cluster nodes will receive the same secret.
///
/// Therefore, this secret backend can't be used for secrets needed before the cluster is up and running.
#[async_trait]
pub trait AuthlySecrets {
    fn name(&self) -> &'static str;

    /// Generate a new versioned secret
    async fn gen_versioned(&self, name: &str) -> anyhow::Result<(Version, Secret)>;

    /// Get a previously generated secret by its version tag
    async fn get_versioned(&self, name: &str, version: &[u8]) -> anyhow::Result<Secret>;
}

#[derive(Default)]
pub struct AuthlySecretsBuilder {
    pub authly_uid: [u8; 32],
    pub bao_url: Option<String>,
    pub bao_token: Option<String>,
}

impl AuthlySecretsBuilder {
    pub fn build(self, client: reqwest::Client) -> Result<Box<dyn AuthlySecrets>, &'static str> {
        if let Some(bao_url) = self.bao_url {
            Ok(Box::new(BaoBackend::new(
                self.authly_uid,
                bao_url,
                self.bao_token,
                client,
            )))
        } else {
            Err("secrets backend not inferrable")
        }
    }
}
