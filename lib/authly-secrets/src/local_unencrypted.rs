//! An insecure secrets backend that just uses one constant key

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{AuthlySecrets, Secret, Version};

pub struct LocalUnencryptedBackend;

const VERSION: &[u8] = b"ENCRYPTIONDISABLED";
const SECRET: [u8; 32] = *b"YOUNEVERSAWTHISDONOTTELLANYBODY!";

#[async_trait]
impl AuthlySecrets for LocalUnencryptedBackend {
    fn name(&self) -> &'static str {
        "local UNENCRYPTED secret store (WARNING!)"
    }

    async fn gen_versioned(&self, _name: &str) -> anyhow::Result<(Version, Secret)> {
        Ok((Version(VERSION.to_vec()), Secret(SECRET)))
    }

    async fn get_versioned(&self, _name: &str, version: &[u8]) -> anyhow::Result<Secret> {
        if version != VERSION {
            return Err(anyhow!(
                "version does not match LocalUnencrypted static version"
            ));
        }

        Ok(Secret(SECRET))
    }
}
