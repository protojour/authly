use std::{collections::HashMap, time::Duration};

use aes_gcm_siv::{
    aead::{Aead, Nonce},
    Aes256GcmSiv, KeyInit,
};
use anyhow::anyhow;
use authly_common::id::PropId;
use authly_db::Db;
use authly_domain::{
    encryption::{AesKey, DecryptedDeks},
    id::BuiltinProp,
};
use authly_secrets::AuthlySecrets;
use rand::{rngs::OsRng, RngCore};
use secrecy::ExposeSecret;
use time::OffsetDateTime;
use tracing::info;
use zeroize::{Zeroize, Zeroizing};

use crate::{db::cryptography_db, IsLeaderDb};

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

                AesKey::new(key.into())
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

pub async fn load_decrypted_deks(
    deps: &impl Db,
    is_leader: IsLeaderDb,
    secrets: &dyn AuthlySecrets,
) -> anyhow::Result<DecryptedDeks> {
    let mut opt_master_version = cryptography_db::load_cr_master_version(deps).await?;

    let deks = if is_leader.0 {
        match opt_master_version {
            None => {
                let decrypted = gen_new_master(secrets).await?;
                cryptography_db::insert_cr_master_version(deps, decrypted.encrypted.clone())
                    .await?;

                gen_prop_deks(deps, &decrypted, is_leader).await?
            }
            Some(version) => {
                let decrypted = decrypt_master(version, secrets).await?;
                gen_prop_deks(deps, &decrypted, is_leader).await?
            }
        }
    } else {
        let decrypted_master = loop {
            match opt_master_version {
                Some(version) => break decrypt_master(version, secrets).await?,
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

    Ok(DecryptedDeks::new(deks))
}

async fn gen_new_master(secrets: &dyn AuthlySecrets) -> anyhow::Result<DecryptedMaster> {
    let (version, secret) = secrets.gen_versioned("master-key").await?;

    Ok(DecryptedMaster {
        encrypted: MasterVersion {
            version: version.0,
            created_at: time::OffsetDateTime::now_utc(),
        },
        key: AesKey::new((*secret.expose_secret()).into()),
    })
}

async fn decrypt_master(
    encrypted: MasterVersion,
    secrets: &dyn AuthlySecrets,
) -> anyhow::Result<DecryptedMaster> {
    let secret = secrets
        .get_versioned("master-key", &encrypted.version)
        .await?;

    Ok(DecryptedMaster {
        encrypted,
        key: AesKey::new((*secret.expose_secret()).into()),
    })
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

            AesKey::load(Zeroizing::new(decrypted_dek))?
        } else {
            let nonce = random_nonce();
            let mut dek = Aes256GcmSiv::generate_key(OsRng);
            let ciph = decrypted_master.key.aes().encrypt(&nonce, dek.as_slice())?;

            new_encrypted_deks.insert(
                id.into(),
                EncryptedDek {
                    nonce,
                    ciph,
                    created_at: time::OffsetDateTime::now_utc(),
                },
            );

            let key = AesKey::new(dek);
            dek.zeroize();
            key
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

pub fn random_nonce() -> Nonce<Aes256GcmSiv> {
    let mut nonce = *Nonce::<Aes256GcmSiv>::from_slice(&[0; 12]); // 96-bits; unique per message
    OsRng.fill_bytes(nonce.as_mut_slice());
    nonce
}

pub fn nonce_from_slice(slice: &[u8]) -> anyhow::Result<Nonce<Aes256GcmSiv>> {
    Nonce::<Aes256GcmSiv>::from_exact_iter(slice.iter().copied())
        .ok_or_else(|| anyhow!("invalid nonce length"))
}
