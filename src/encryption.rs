use std::{collections::HashMap, time::Duration};

use aes_gcm_siv::{
    aead::{Aead, Nonce},
    Aes256GcmSiv, KeyInit,
};
use anyhow::{anyhow, Context};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use crate::{
    db::{config_db, Db},
    id::BuiltinID,
    EnvConfig,
};

pub struct DecryptedDeks {
    pub deks: HashMap<BuiltinID, DecryptedDek>,
}

impl DecryptedDeks {
    pub fn get(&self, id: BuiltinID) -> Option<&DecryptedDek> {
        self.deks.get(&id)
    }
}

#[derive(Clone)]
pub struct MasterVersion {
    pub kind: String,
    pub version: Vec<u8>,
    pub created_at: time::OffsetDateTime,
}

struct DecryptedMaster {
    encrypted: MasterVersion,
    plaintext: Vec<u8>,
}

#[derive(Clone)]
pub struct EncryptedDek {
    pub nonce: Vec<u8>,
    pub ciph: Vec<u8>,
    pub created_at: time::OffsetDateTime,
}

pub struct DecryptedDek {
    pub aes: Aes256GcmSiv,
}

#[derive(Deserialize)]
struct Output {
    pub version: Hex,
    pub plaintext: Hex,
}

#[derive(Clone, Deserialize)]
struct Hex(#[serde(deserialize_with = "hex::serde::deserialize")] pub Vec<u8>);

pub async fn load_decrypted_deks(
    deps: &impl Db,
    is_leader: bool,
    env_config: &EnvConfig,
) -> anyhow::Result<DecryptedDeks> {
    let mut opt_master_version = config_db::load_cr_master_version(deps).await?;

    let deks = if is_leader {
        match opt_master_version {
            None => {
                let decrypted = gen_new_master(env_config).await?;
                config_db::insert_cr_master_version(deps, decrypted.encrypted.clone()).await?;

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

                    opt_master_version = config_db::load_cr_master_version(deps).await?;
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
            kind: "crypt".to_string(),
            version: output.version.0,
            created_at: time::OffsetDateTime::now_utc(),
        },
        plaintext: output.plaintext.0,
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
        plaintext: output.plaintext.0,
    })
}

async fn gen_prop_deks(
    deps: &impl Db,
    decrypted_master: &DecryptedMaster,
    is_leader: bool,
) -> anyhow::Result<HashMap<BuiltinID, DecryptedDek>> {
    let old_encrypted_deks = config_db::list_all_cr_prop_deks(deps).await?;
    let mut new_encrypted_deks: HashMap<BuiltinID, EncryptedDek> = Default::default();
    let mut decrypted_deks: HashMap<BuiltinID, DecryptedDek> = Default::default();

    let master_key = Aes256GcmSiv::new_from_slice(&decrypted_master.plaintext)
        .context("could not make cipher from master plaintext")?;

    for id in all_encrypted_props() {
        let decrypted_dek = if let Some(encrypted) = old_encrypted_deks.get(&id) {
            let nonce = nonce_from_slice(&encrypted.nonce)?;
            let dek = master_key.decrypt(&nonce, encrypted.ciph.as_ref())?;

            DecryptedDek {
                aes: Aes256GcmSiv::new_from_slice(dek.as_slice())?,
            }
        } else {
            let nonce = gen_nonce();
            let dek = Aes256GcmSiv::generate_key(OsRng);

            let encrypted = master_key.encrypt(&nonce, dek.as_slice())?;

            new_encrypted_deks.insert(
                id,
                EncryptedDek {
                    nonce: nonce.to_vec(),
                    ciph: encrypted,
                    created_at: time::OffsetDateTime::now_utc(),
                },
            );

            DecryptedDek {
                aes: Aes256GcmSiv::new(&dek),
            }
        };

        decrypted_deks.insert(id, decrypted_dek);
    }

    if is_leader && !new_encrypted_deks.is_empty() {
        config_db::insert_crypt_prop_deks(deps, new_encrypted_deks).await?;
    }

    Ok(decrypted_deks)
}

fn all_encrypted_props() -> impl Iterator<Item = BuiltinID> {
    BuiltinID::iter().filter(|id| id.is_encrypted_prop())
}

pub fn gen_nonce() -> Nonce<Aes256GcmSiv> {
    let mut nonce = *Nonce::<Aes256GcmSiv>::from_slice(&[0; 12]); // 96-bits; unique per message
    OsRng.fill_bytes(nonce.as_mut_slice());
    nonce
}

pub fn nonce_from_slice(slice: &[u8]) -> anyhow::Result<Nonce<Aes256GcmSiv>> {
    Nonce::<Aes256GcmSiv>::from_exact_iter(slice.iter().copied())
        .ok_or_else(|| anyhow!("invalid nonce length"))
}
