//! configuration stored in the database

use std::{collections::HashMap, time::Duration};

use aes_gcm_siv::aead::Aead;
use anyhow::anyhow;
use authly_common::id::ObjId;
use hiqlite::{params, Client, Param};
use indoc::indoc;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{debug, info};

use crate::{
    cert::Cert,
    encryption::{gen_nonce, nonce_from_slice, DecryptedDeks, EncryptedDek, MasterVersion},
    id::BuiltinID,
    DynamicConfig,
};

use super::{Convert, Db, DbError, Row};

#[derive(Error, Debug)]
pub enum ConfigDbError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("crypto error: {0}")]
    Crypto(anyhow::Error),
}

pub async fn load_cr_master_version(
    deps: &impl Db,
) -> Result<Option<MasterVersion>, ConfigDbError> {
    let rows = deps
        .query_raw(
            "SELECT kind, version, created_at FROM cr_master_version".into(),
            params!(),
        )
        .await?;

    let Some(mut row) = rows.into_iter().next() else {
        return Ok(None);
    };

    Ok(Some(MasterVersion {
        kind: row.get_text("kind"),
        version: row.get_blob("version"),
        created_at: OffsetDateTime::from_unix_timestamp(row.get_int("created_at")).unwrap(),
    }))
}

pub async fn insert_cr_master_version(
    deps: &impl Db,
    ver: MasterVersion,
) -> Result<(), ConfigDbError> {
    deps.execute(
        "INSERT INTO cr_master_version (kind, version, created_at) VALUES ($1, $2, $3)".into(),
        params!(ver.kind, ver.version, ver.created_at.unix_timestamp()),
    )
    .await?;

    Ok(())
}

pub async fn list_all_cr_prop_deks(
    deps: &impl Db,
) -> Result<HashMap<BuiltinID, EncryptedDek>, ConfigDbError> {
    let rows = deps
        .query_raw(
            "SELECT prop_id, nonce, ciph, created_at FROM cr_prop_dek".into(),
            params!(),
        )
        .await?;

    Ok(rows
        .into_iter()
        .filter_map(|mut row| {
            let prop_id = ObjId::from_bytes(&row.get_blob("prop_id"))?;
            let builtin_id = BuiltinID::try_from(prop_id.to_uint() as u32).ok()?;

            Some((
                builtin_id,
                EncryptedDek {
                    nonce: row.get_blob("nonce"),
                    ciph: row.get_blob("ciph"),
                    created_at: time::OffsetDateTime::from_unix_timestamp(
                        row.get_int("created_at"),
                    )
                    .unwrap(),
                },
            ))
        })
        .collect())
}

pub async fn insert_crypt_prop_deks(
    deps: &impl Db,
    deks: HashMap<BuiltinID, EncryptedDek>,
) -> Result<(), ConfigDbError> {
    for (id, dek) in deks {
        deps.execute(
            "INSERT INTO cr_prop_dek (prop_id, nonce, ciph, created_at) VALUES ($1, $2, $3, $4)"
                .into(),
            params!(
                id.to_obj_id().as_param(),
                dek.nonce,
                dek.ciph,
                dek.created_at.unix_timestamp()
            ),
        )
        .await?;
    }

    Ok(())
}

pub async fn load_db_config(
    db: &Client,
    deks: &DecryptedDeks,
) -> Result<DynamicConfig, ConfigDbError> {
    let is_leader = db.is_leader_db().await;

    let local_ca = match load_tlskey("local_ca", db, deks).await? {
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

                save_tlskey(&local_ca, "local_ca", db, deks).await?;

                local_ca
            } else {
                loop {
                    info!("waiting for leader to generate local CA");
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    if let Some(local_ca) = load_tlskey("local_ca", db, deks).await? {
                        break local_ca;
                    }
                }
            }
        }
    };

    let jwt_decoding_key = {
        let (_, x509_cert) = x509_parser::parse_x509_certificate(&local_ca.der).unwrap();

        // Assume that EC is always used
        jsonwebtoken::DecodingKey::from_ec_der(&x509_cert.public_key().subject_public_key.data)
    };

    Ok(DynamicConfig {
        local_ca,
        jwt_decoding_key,
    })
}

async fn load_tlskey(
    purpose: &str,
    db: &Client,
    deks: &DecryptedDeks,
) -> Result<Option<Cert<KeyPair>>, ConfigDbError> {
    let rows = db
        .query_raw(
            "SELECT cert, key_nonce, key_ciph FROM tlskey WHERE purpose = $1",
            params!(purpose),
        )
        .await?;

    let Some(mut row) = rows.into_iter().next() else {
        return Ok(None);
    };

    let cert_der = CertificateDer::from(row.get::<Vec<u8>>("cert"));

    let dek = deks
        .get(BuiltinID::PropLocalCA)
        .ok_or_else(|| ConfigDbError::Crypto(anyhow!("no decryption key for local CA key")))?;

    let nonce = nonce_from_slice(&row.get::<Vec<_>>("key_nonce")).map_err(ConfigDbError::Crypto)?;
    let private_key_ciph: Vec<u8> = row.get("key_ciph");

    let private_key_plaintext = dek
        .aes
        .decrypt(&nonce, private_key_ciph.as_ref())
        .map_err(|err| ConfigDbError::Crypto(err.into()))?;

    let private_key_der = PrivateKeyDer::try_from(private_key_plaintext)
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
    deks: &DecryptedDeks,
) -> Result<(), ConfigDbError> {
    let cert_der = cert.der.to_vec();
    let private_key_der = cert.key.serialize_der();

    let dek = deks
        .get(BuiltinID::PropLocalCA)
        .ok_or_else(|| ConfigDbError::Crypto(anyhow!("no decryption key for local CA key")))?;
    let nonce = gen_nonce();

    let key_ciph = dek
        .aes
        .encrypt(&nonce, private_key_der.as_ref())
        .map_err(|err| ConfigDbError::Crypto(err.into()))?;

    db.execute(
        indoc! {
            "
            INSERT INTO tlskey (purpose, expires_at, cert, key_nonce, key_ciph)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO UPDATE SET expires_at = $2, cert = $3, key_nonce = $4, key_ciph = $5
            "
        },
        params!(
            purpose,
            cert.params.not_after.unix_timestamp(),
            cert_der,
            nonce.to_vec(),
            key_ciph
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
