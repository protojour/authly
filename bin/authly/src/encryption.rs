use std::time::Duration;

use aes_gcm_siv::{aead::Nonce, Aes256GcmSiv};
use anyhow::anyhow;
use authly_db::Db;
use authly_domain::{
    encryption::{gen_prop_deks, AesKey, DecryptedDeks, DecryptedMaster, MasterVersion},
    id::BuiltinProp,
    repo::crypto_repo,
    IsLeaderDb,
};
use authly_secrets::AuthlySecrets;
use secrecy::ExposeSecret;
use tracing::info;

pub async fn load_decrypted_deks(
    deps: &impl Db,
    is_leader: IsLeaderDb,
    secrets: &dyn AuthlySecrets,
) -> anyhow::Result<DecryptedDeks> {
    let mut opt_master_version = crypto_repo::load_cr_master_version(deps).await?;

    let deks = if is_leader.0 {
        match opt_master_version {
            None => {
                let decrypted = gen_new_master(secrets).await?;
                crypto_repo::insert_cr_master_version(deps, decrypted.encrypted.clone()).await?;

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

                    opt_master_version = crypto_repo::load_cr_master_version(deps).await?;
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

fn all_encrypted_props() -> impl Iterator<Item = BuiltinProp> {
    BuiltinProp::iter().filter(|id| id.is_encrypted())
}

pub fn nonce_from_slice(slice: &[u8]) -> anyhow::Result<Nonce<Aes256GcmSiv>> {
    Nonce::<Aes256GcmSiv>::from_exact_iter(slice.iter().copied())
        .ok_or_else(|| anyhow!("invalid nonce length"))
}
