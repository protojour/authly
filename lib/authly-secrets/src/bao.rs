use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use hexhex::hex;
use rand::{rngs::OsRng, Rng};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{AuthlySecrets, Secret, Version};

pub struct BaoBackend {
    authly_uid: [u8; 32],
    url: String,
    client: reqwest::Client,
    token: Arc<Mutex<Token>>,
}

struct Token {
    value: Option<Arc<String>>,
    ephemeral: bool,
}

#[derive(Error, Debug)]
enum GetError {
    #[error("not found")]
    NotFound,
    #[error("network")]
    Network(#[from] reqwest::Error),
    #[error("other")]
    Other(#[from] anyhow::Error),
}

impl BaoBackend {
    pub fn new(
        authly_uid: [u8; 32],
        url: String,
        token: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            authly_uid,
            url,
            token: Arc::new(Mutex::new(if let Some(token) = token {
                Token {
                    value: Some(Arc::new(token)),
                    ephemeral: false,
                }
            } else {
                Token {
                    value: None,
                    ephemeral: true,
                }
            })),
            client,
        }
    }

    async fn get_token(&self) -> anyhow::Result<Arc<String>> {
        let url = &self.url;
        let value = {
            let mut lock = self.token.lock().await;
            if !lock.ephemeral {
                return Ok(lock.value.clone().unwrap());
            } else if let Some(value) = &lock.value {
                return Ok(value.clone());
            }

            // NB: only kubernetes Auth for now
            let svc_token =
                std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
                    .unwrap();
            let bao_output: BaoAuthOutput = self
                .client
                .post(format!("{url}/v1/auth/kubernetes/login"))
                .json(&json!({
                    "role": "authly",
                    "jwt": svc_token,
                }))
                .send()
                .await?
                .error_for_status()
                .context("fatal: bao authentication error")?
                .json()
                .await?;

            let value = Arc::new(bao_output.auth.client_token);
            lock.value = Some(value.clone());
            value
        };

        // delete token from memory after fixed delay
        tokio::spawn({
            let token = self.token.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut lock = token.lock().await;
                lock.value = None;
            }
        });

        Ok(value)
    }

    async fn gen_secret(&self, name: &str) -> anyhow::Result<(Version, Secret)> {
        let token = self.get_token().await?;
        let url = &self.url;
        let authly_uid = hex(self.authly_uid);

        let secret = {
            let mut secret: [u8; 32] = [0; 32];
            OsRng.fill(secret.as_mut_slice());
            secret
        };

        let bao_output: BaoCreateSecretOutput = self
            .client
            .post(format!("{url}/v1/secret/data/authly-{name}-{authly_uid}"))
            .header("x-vault-token", token.as_ref())
            .json(&json!({
                "data": {
                    "secret": hex(secret).to_string(),
                }
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let version = bao_output.data.version;

        Ok((Version(version.to_be_bytes().to_vec()), Secret(secret)))
    }

    async fn try_get_secret(&self, name: &str, version: Option<&[u8]>) -> Result<Secret, GetError> {
        let token = self.get_token().await?;
        let url = &self.url;
        let authly_uid = hex(self.authly_uid);

        let mut url = format!("{url}/v1/secret/data/authly-{name}-{authly_uid}");

        if let Some(version) = version {
            let version: [u8; 8] = version
                .try_into()
                .context("invalid secret version for bao backend")?;
            let version = u64::from_be_bytes(version);

            url.push_str(&format!("?version={version}"));
        }

        let bao_output: BaoReadSecretOutput = self
            .client
            .get(url)
            .header("x-vault-token", token.as_ref())
            .send()
            .await?
            .error_for_status()
            .map_err(|err| {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    GetError::NotFound
                } else {
                    GetError::Other(err.into())
                }
            })?
            .json()
            .await?;

        let secret = hexhex::decode(&bao_output.data.data.secret).context("must be hex encoded")?;

        Ok(Secret(secret.try_into().map_err(|_err| {
            anyhow!("bao: unexpected secret length")
        })?))
    }
}

#[async_trait]
impl AuthlySecrets for BaoBackend {
    fn name(&self) -> &'static str {
        "bao"
    }

    async fn gen_versioned(&self, name: &str) -> anyhow::Result<(Version, Secret)> {
        Ok(self.gen_secret(name).await?)
    }

    async fn get_versioned(&self, name: &str, version: &[u8]) -> anyhow::Result<Secret> {
        Ok(self.try_get_secret(name, Some(version)).await?)
    }
}

#[derive(Deserialize)]
struct BaoAuthOutput {
    pub auth: BaoAuthData,
}

#[derive(Deserialize)]
struct BaoAuthData {
    pub client_token: String,
}

#[derive(Deserialize)]
struct BaoCreateSecretOutput {
    pub data: BaoCreateSecretData,
}

#[derive(Deserialize)]
struct BaoCreateSecretData {
    version: u64,
}

#[derive(Deserialize)]
struct BaoReadSecretOutput {
    pub data: BaoReadSecretData,
}

#[derive(Deserialize)]
struct BaoReadSecretData {
    pub data: BaoReadSecretDataData,
}

#[derive(Deserialize)]
struct BaoReadSecretDataData {
    pub secret: String,
}
