use std::{collections::HashMap, fmt::Debug, time::Duration};

use aes_gcm_siv::{
    aead::{Aead, Nonce},
    Aes256GcmSiv, Key, KeyInit,
};
use anyhow::{anyhow, Context};
use authly_common::id::PropId;
use authly_db::Db;
use rand::{rngs::OsRng, Rng, RngCore};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use tracing::info;

use crate::{db::cryptography_db, id::BuiltinProp, util::serde::Hex, EnvConfig, IsLeaderDb};

/// The set of Data Encryption Keys used by authly
#[derive(Default, Debug)]
pub struct DecryptedDeks {
    deks: HashMap<PropId, AesKey>,
}

impl DecryptedDeks {
    pub fn new(deks: HashMap<PropId, AesKey>) -> Self {
        Self { deks }
    }

    pub fn get(&self, id: PropId) -> anyhow::Result<&AesKey> {
        self.deks
            .get(&id)
            .ok_or_else(|| anyhow!("no DEK present for {id}"))
    }
}

#[derive(Clone)]
pub struct MasterVersion {
    pub version: Vec<u8>,
    pub created_at: time::OffsetDateTime,
}

pub struct DecryptedMaster {
    encrypted: MasterVersion,
    key: AesKey,
}

impl DecryptedMaster {
    pub fn fake_for_test() -> Self {
        Self {
            encrypted: MasterVersion {
                version: vec![],
                created_at: OffsetDateTime::now_utc(),
            },
            key: {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(key.as_mut_slice());

                AesKey {
                    key: load_key(key).unwrap(),
                }
            },
        }
    }
}

#[derive(Clone)]
pub struct EncryptedDek {
    pub nonce: Nonce<Aes256GcmSiv>,
    pub ciph: Vec<u8>,
    pub created_at: time::OffsetDateTime,
}

pub struct AesKey {
    key: Key<Aes256GcmSiv>,
}

impl Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesKey").finish()
    }
}

impl AesKey {
    /// Make an AES cipher for this key
    pub fn aes(&self) -> Aes256GcmSiv {
        Aes256GcmSiv::new(&self.key)
    }

    // Use blake3 to produce a fingerprint of the given data, with this Dek as "salt"
    pub fn fingerprint(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.key.as_slice());
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Deserialize)]
struct PalOutput {
    pub version: Hex,
    pub plaintext: Hex,
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
    pub master_key: Hex<[u8; 32]>,
}

pub async fn load_decrypted_deks(
    deps: &impl Db,
    is_leader: IsLeaderDb,
    env_config: &EnvConfig,
) -> anyhow::Result<DecryptedDeks> {
    let mut opt_master_version = cryptography_db::load_cr_master_version(deps).await?;

    let deks = if is_leader.0 {
        match opt_master_version {
            None => {
                let decrypted = gen_new_master(env_config).await?;
                cryptography_db::insert_cr_master_version(deps, decrypted.encrypted.clone())
                    .await?;

                gen_prop_deks(deps, &decrypted, is_leader).await?
            }
            Some(version) => {
                let decrypted = decrypt_master(version, env_config).await?;
                gen_prop_deks(deps, &decrypted, is_leader).await?
            }
        }
    } else {
        let decrypted_master = loop {
            match opt_master_version {
                Some(version) => break decrypt_master(version, env_config).await?,
                None => {
                    info!("waiting for leader to initialize master version");
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    opt_master_version = cryptography_db::load_cr_master_version(deps).await?;
                }
            }
        };

        let encrypted_props_len = all_encrypted_props().count();

        loop {
            let deks = gen_prop_deks(deps, &decrypted_master, is_leader).await?;
            if deks.len() < encrypted_props_len {
                info!("not enough deks; waiting for leader");
                tokio::time::sleep(Duration::from_secs(1)).await;
            } else {
                break deks;
            }
        }
    };

    Ok(DecryptedDeks { deks })
}

async fn gen_new_master(env_config: &EnvConfig) -> anyhow::Result<DecryptedMaster> {
    if let Some(bao_url) = &env_config.bao_url {
        let id = &env_config.id;
        let Some(bao_token) = &env_config.bao_token else {
            return Err(anyhow!("fatal: no bao token set"));
        };
        let mut plaintext: [u8; 32] = [0; 32];

        OsRng.fill(plaintext.as_mut_slice());

        let master = Hex(plaintext.to_vec());

        let vault_output: BaoCreateSecretOutput = reqwest::Client::new()
            .post(format!("{bao_url}/v1/secret/data/authly-master-key-{id}"))
            .header("x-vault-token", bao_token.clone())
            .json(&json!({
                "data": {
                    "master_key": master,
                }
            }))
            .send()
            .await?
            .error_for_status()
            .context("fatal: vault error")?
            .json()
            .await?;

        let version = vault_output.data.version;

        Ok(DecryptedMaster {
            encrypted: MasterVersion {
                version: version.to_be_bytes().to_vec(),
                created_at: time::OffsetDateTime::now_utc(),
            },
            key: AesKey {
                key: load_key(master.0)?,
            },
        })
    } else if let Some(pal_url) = &env_config.pal_url {
        let pal_output: PalOutput = reqwest::Client::new()
            .post(format!("{pal_url}/api/v0/key"))
            .json(&json!({
                "key_id": "authly-master",
            }))
            .send()
            .await?
            .error_for_status()
            .context("fatal: authly-pal error")?
            .json()
            .await?;

        Ok(DecryptedMaster {
            encrypted: MasterVersion {
                version: pal_output.version.0,
                created_at: time::OffsetDateTime::now_utc(),
            },
            key: AesKey {
                key: load_key(pal_output.plaintext.0)?,
            },
        })
    } else {
        Err(anyhow!("fatal: no secret store configured"))
    }
}

async fn decrypt_master(
    encrypted: MasterVersion,
    env_config: &EnvConfig,
) -> anyhow::Result<DecryptedMaster> {
    if let Some(bao_url) = &env_config.bao_url {
        let id = &env_config.id;
        let version: [u8; 8] = encrypted.version.as_slice().try_into().expect("");
        let version = u64::from_be_bytes(version);
        let Some(bao_token) = &env_config.bao_token else {
            return Err(anyhow!("fatal: no bao token set"));
        };
        let vault_output: BaoReadSecretOutput = reqwest::Client::new()
            .get(format!(
                "{bao_url}/v1/secret/data/authly-master-key-{id}?version={version}"
            ))
            .header("x-vault-token", bao_token.clone())
            .send()
            .await?
            .error_for_status()
            .context("fatal: vault error")?
            .json()
            .await?;
        Ok(DecryptedMaster {
            encrypted,
            key: AesKey {
                key: load_key(vault_output.data.data.master_key.0.into_iter())?,
            },
        })
    } else if let Some(pal_url) = &env_config.pal_url {
        let pal_output: PalOutput = reqwest::Client::new()
            .post(format!("{pal_url}/api/v0/key"))
            .json(&json!({
                "key_id": "authly-master",
                "version": hexhex::hex(&encrypted.version).to_string(),
            }))
            .send()
            .await?
            .error_for_status()
            .context("fatal: authly-crypt error")?
            .json()
            .await?;

        Ok(DecryptedMaster {
            encrypted,
            key: AesKey {
                key: load_key(pal_output.plaintext.0)?,
            },
        })
    } else {
        Err(anyhow!("fatal: no secret store configured"))
    }
}

pub async fn gen_prop_deks(
    deps: &impl Db,
    decrypted_master: &DecryptedMaster,
    is_leader: IsLeaderDb,
) -> anyhow::Result<HashMap<PropId, AesKey>> {
    let old_encrypted_deks = cryptography_db::list_all_cr_prop_deks(deps).await?;
    let mut new_encrypted_deks: HashMap<PropId, EncryptedDek> = Default::default();
    let mut decrypted_deks: HashMap<PropId, AesKey> = Default::default();

    for id in all_encrypted_props() {
        let decrypted_dek = if let Some(encrypted) = old_encrypted_deks.get(&id) {
            let nonce = encrypted.nonce;
            let decrypted_dek = decrypted_master
                .key
                .aes()
                .decrypt(&nonce, encrypted.ciph.as_ref())?;

            AesKey {
                key: load_key(decrypted_dek)?,
            }
        } else {
            let nonce = random_nonce();
            let dek = Aes256GcmSiv::generate_key(OsRng);
            let ciph = decrypted_master.key.aes().encrypt(&nonce, dek.as_slice())?;

            new_encrypted_deks.insert(
                id.into(),
                EncryptedDek {
                    nonce,
                    ciph,
                    created_at: time::OffsetDateTime::now_utc(),
                },
            );

            AesKey { key: dek }
        };

        decrypted_deks.insert(id.into(), decrypted_dek);
    }

    if is_leader.0 && !new_encrypted_deks.is_empty() {
        cryptography_db::insert_cr_prop_deks(deps, new_encrypted_deks).await?;
    }

    Ok(decrypted_deks)
}

fn all_encrypted_props() -> impl Iterator<Item = BuiltinProp> {
    BuiltinProp::iter().filter(|id| id.is_encrypted())
}

fn load_key(bytes: impl IntoIterator<Item = u8>) -> anyhow::Result<Key<Aes256GcmSiv>> {
    Key::<Aes256GcmSiv>::from_exact_iter(bytes).ok_or_else(|| anyhow!("invalid key length"))
}

pub fn random_nonce() -> Nonce<Aes256GcmSiv> {
    let mut nonce = *Nonce::<Aes256GcmSiv>::from_slice(&[0; 12]); // 96-bits; unique per message
    OsRng.fill_bytes(nonce.as_mut_slice());
    nonce
}

pub fn nonce_from_slice(slice: &[u8]) -> anyhow::Result<Nonce<Aes256GcmSiv>> {
    Nonce::<Aes256GcmSiv>::from_exact_iter(slice.iter().copied())
        .ok_or_else(|| anyhow!("invalid nonce length"))
}
