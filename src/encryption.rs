use std::{collections::HashMap, fmt::Debug, time::Duration};

use aes_gcm_siv::{
    aead::{Aead, Nonce},
    Aes256GcmSiv, Key, KeyInit,
};
use anyhow::{anyhow, Context};
use authly_common::id::ObjId;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use crate::{
    db::{cryptography_db, Db},
    id::BuiltinID,
    serde_util::Hex,
    EnvConfig,
};

/// The set of Data Encryption Keys used by authly
#[derive(Default, Debug)]
pub struct DecryptedDeks {
    deks: HashMap<ObjId, AesKey>,
}

impl DecryptedDeks {
    pub fn get(&self, id: ObjId) -> anyhow::Result<&AesKey> {
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

struct DecryptedMaster {
    encrypted: MasterVersion,
    key: AesKey,
}

#[derive(Clone)]
pub struct EncryptedDek {
    pub nonce: Vec<u8>,
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
struct Output {
    pub version: Hex,
    pub plaintext: Hex,
}

pub async fn load_decrypted_deks(
    deps: &impl Db,
    is_leader: bool,
    env_config: &EnvConfig,
) -> anyhow::Result<DecryptedDeks> {
    let mut opt_master_version = cryptography_db::load_cr_master_version(deps).await?;

    let deks = if is_leader {
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
    let pal_url = &env_config.pal_url;
    let output: Output = reqwest::Client::new()
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
            version: output.version.0,
            created_at: time::OffsetDateTime::now_utc(),
        },
        key: AesKey {
            key: load_key(output.plaintext.0)?,
        },
    })
}

async fn decrypt_master(
    encrypted: MasterVersion,
    env_config: &EnvConfig,
) -> anyhow::Result<DecryptedMaster> {
    let pal_url = &env_config.pal_url;
    let output: Output = reqwest::Client::new()
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
            key: load_key(output.plaintext.0)?,
        },
    })
}

async fn gen_prop_deks(
    deps: &impl Db,
    decrypted_master: &DecryptedMaster,
    is_leader: bool,
) -> anyhow::Result<HashMap<ObjId, AesKey>> {
    let old_encrypted_deks = cryptography_db::list_all_cr_prop_deks(deps).await?;
    let mut new_encrypted_deks: HashMap<ObjId, EncryptedDek> = Default::default();
    let mut decrypted_deks: HashMap<ObjId, AesKey> = Default::default();

    for id in all_encrypted_props() {
        let decrypted_dek = if let Some(encrypted) = old_encrypted_deks.get(&id) {
            let nonce = nonce_from_slice(&encrypted.nonce)?;
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
                id.to_obj_id(),
                EncryptedDek {
                    nonce: nonce.to_vec(),
                    ciph,
                    created_at: time::OffsetDateTime::now_utc(),
                },
            );

            AesKey { key: dek }
        };

        decrypted_deks.insert(id.to_obj_id(), decrypted_dek);
    }

    if is_leader && !new_encrypted_deks.is_empty() {
        cryptography_db::insert_cr_prop_deks(deps, new_encrypted_deks).await?;
    }

    Ok(decrypted_deks)
}

fn all_encrypted_props() -> impl Iterator<Item = BuiltinID> {
    BuiltinID::iter().filter(|id| id.is_encrypted_prop())
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
