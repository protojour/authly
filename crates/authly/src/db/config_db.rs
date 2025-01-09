//! configuration stored in the database

use std::time::Duration;

use anyhow::anyhow;
use hiqlite::{params, Client, Param};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tracing::{debug, info};

use crate::{cert::Cert, DynamicConfig};

use super::DbError;

#[derive(Error, Debug)]
pub enum ConfigDbError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("crypto error: {0}")]
    Crypto(anyhow::Error),
}

pub async fn load_db_config(db: &Client) -> Result<DynamicConfig, ConfigDbError> {
    let is_leader = db.is_leader_db().await;

    let local_ca = match load_tlskey("local_ca", db).await? {
        Some(local_ca) => {
            debug!(
                "reusing stored CA, expires at {}",
                local_ca.params.not_after
            );
            local_ca
        }
        None => {
            if is_leader {
                let local_ca = Cert::new_authly_ca();

                debug!(
                    "generating new local CA expiring at {}",
                    local_ca.params.not_after
                );

                save_tlskey(&local_ca, "local_ca", db).await?;

                local_ca
            } else {
                loop {
                    info!("waiting for leader to generate local CA");
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    if let Some(local_ca) = load_tlskey("local_ca", db).await? {
                        break local_ca;
                    }
                }
            }
        }
    };

    Ok(DynamicConfig { local_ca })
}

async fn load_tlskey(purpose: &str, db: &Client) -> Result<Option<Cert<KeyPair>>, ConfigDbError> {
    let rows = db
        .query_raw(
            "SELECT cert, private_key FROM tlskey WHERE purpose = $1",
            params!(purpose),
        )
        .await?;

    let Some(mut row) = rows.into_iter().next() else {
        return Ok(None);
    };

    let cert_der = CertificateDer::from(row.get::<Vec<u8>>("cert"));
    let private_key_der = PrivateKeyDer::try_from(row.get::<Vec<u8>>("private_key"))
        .map_err(|msg| ConfigDbError::Crypto(anyhow!("private key: {msg}")))?;

    let cert = Cert {
        params: CertificateParams::from_ca_cert_der(&cert_der)?,
        der: cert_der,
        key: KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_ECDSA_P256_SHA256)?,
    };

    Ok(Some(cert))
}

async fn save_tlskey(
    cert: &Cert<KeyPair>,
    purpose: &str,
    db: &Client,
) -> Result<(), ConfigDbError> {
    let cert_der = cert.der.to_vec();
    let private_key_der = cert.key.serialize_der();

    db
        .execute(
            "INSERT INTO tlskey (purpose, expires_at, cert, private_key) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET expires_at = $2, cert = $3, private_key = $4",
            params!(
                purpose,
                cert.params.not_after.unix_timestamp(),
                cert_der,
                private_key_der
            ),
        )
        .await?;

    Ok(())
}

impl From<hiqlite::Error> for ConfigDbError {
    fn from(value: hiqlite::Error) -> Self {
        Self::Db(DbError::Hiqlite(value))
    }
}

impl From<rcgen::Error> for ConfigDbError {
    fn from(value: rcgen::Error) -> Self {
        Self::Crypto(value.into())
    }
}
