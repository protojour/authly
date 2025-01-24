//! cryptography-oriented things stored in the DB (secret information is encrypted!)

use std::{collections::HashMap, time::Duration};

use aes_gcm_siv::aead::Aead;
use anyhow::{anyhow, Context};
use authly_common::id::{Eid, ObjId};
use hiqlite::{params, Client, Param};
use indoc::indoc;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{debug, info};

use crate::{
    cert::{Cert, MakeSigningRequest},
    encryption::{nonce_from_slice, random_nonce, DecryptedDeks, EncryptedDek, MasterVersion},
    id::BuiltinID,
    TlsParams,
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
            "SELECT version, created_at FROM cr_master_version".into(),
            params!(),
        )
        .await?;

    let Some(mut row) = rows.into_iter().next() else {
        return Ok(None);
    };

    Ok(Some(MasterVersion {
        version: row.get_blob("version"),
        created_at: OffsetDateTime::from_unix_timestamp(row.get_int("created_at")).unwrap(),
    }))
}

pub async fn insert_cr_master_version(
    deps: &impl Db,
    ver: MasterVersion,
) -> Result<(), ConfigDbError> {
    deps.execute(
        "INSERT INTO cr_master_version (version, created_at) VALUES ($1, $2)".into(),
        params!(ver.version, ver.created_at.unix_timestamp()),
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

pub async fn insert_cr_prop_deks(
    deps: &impl Db,
    deks: HashMap<ObjId, EncryptedDek>,
) -> Result<(), ConfigDbError> {
    for (id, dek) in deks {
        deps.execute(
            "INSERT INTO cr_prop_dek (prop_id, nonce, ciph, created_at) VALUES ($1, $2, $3, $4)"
                .into(),
            params!(
                id.as_param(),
                dek.nonce,
                dek.ciph,
                dek.created_at.unix_timestamp()
            ),
        )
        .await?;
    }

    Ok(())
}

/// Load initial TLS params.
///
/// If starting up for the first time, then self-signed CA and identity is generated.
/// These can be changed after the fact, after registering an authly authority for the first time.
pub async fn load_tls_params(
    db: &Client,
    deks: &DecryptedDeks,
) -> Result<TlsParams, ConfigDbError> {
    let is_leader = db.is_leader_db().await;

    // Load or generate the local CA
    let local_ca = load_or_generate_tlskey(
        is_leader,
        BuiltinID::PropLocalCA,
        Cert::new_authly_ca,
        db,
        deks,
    )
    .await?;

    // Load or generate the self-signed identity
    let identity = load_or_generate_tlskey(
        is_leader,
        BuiltinID::PropTlsIdentity,
        || {
            let self_eid = Eid::random();
            local_ca.sign(
                KeyPair::generate()
                    .unwrap()
                    .client_cert(&self_eid.to_string(), time::Duration::days(365 * 100)),
            )
        },
        db,
        deks,
    )
    .await?;

    Ok(TlsParams::from_keys(local_ca, identity))
}

async fn load_or_generate_tlskey(
    is_leader: bool,
    property: BuiltinID,
    generator: impl FnOnce() -> Cert<KeyPair>,
    db: &Client,
    deks: &DecryptedDeks,
) -> Result<Cert<KeyPair>, ConfigDbError> {
    match try_load_tlskey(property, db, deks).await? {
        Some(cert_key) => {
            debug!(
                "reusing {property:?}, expires at {}",
                cert_key.params.not_after
            );
            Ok(cert_key)
        }
        None => {
            if is_leader {
                let cert_key = generator();

                debug!(
                    "generating new {property:?} expiring at {}",
                    cert_key.params.not_after
                );

                save_tlskey(&cert_key, property, db, deks).await?;

                Ok(cert_key)
            } else {
                loop {
                    info!("waiting for leader to generate {property:?}");
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    if let Some(local_ca) = try_load_tlskey(property, db, deks).await? {
                        return Ok(local_ca);
                    }
                }
            }
        }
    }
}

async fn try_load_tlskey(
    property: BuiltinID,
    db: &Client,
    deks: &DecryptedDeks,
) -> Result<Option<Cert<KeyPair>>, ConfigDbError> {
    let rows = db
        .query_raw(
            "SELECT cert, key_nonce, key_ciph FROM tlskey WHERE purpose = $1",
            params!(purpose(property)),
        )
        .await?;

    let Some(mut row) = rows.into_iter().next() else {
        return Ok(None);
    };

    let cert_der = CertificateDer::from(row.get::<Vec<u8>>("cert"));

    let dek = deks
        .get(property.to_obj_id())
        .map_err(ConfigDbError::Crypto)?;

    let nonce = nonce_from_slice(&row.get::<Vec<_>>("key_nonce")).map_err(ConfigDbError::Crypto)?;
    let private_key_ciph: Vec<u8> = row.get("key_ciph");

    let private_key_plaintext = dek
        .aes()
        .decrypt(&nonce, private_key_ciph.as_ref())
        .context("FATAL: Encryption key has changed, unable to decrypt TLS key")
        .map_err(ConfigDbError::Crypto)?;

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
    property: BuiltinID,
    db: &Client,
    deks: &DecryptedDeks,
) -> Result<(), ConfigDbError> {
    let cert_der = cert.der.to_vec();
    let private_key_der = cert.key.serialize_der();

    let dek = deks
        .get(property.to_obj_id())
        .map_err(ConfigDbError::Crypto)?;
    let nonce = random_nonce();
    let key_ciph = dek
        .aes()
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
            purpose(property),
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

fn purpose(prop_id: BuiltinID) -> &'static str {
    match prop_id {
        BuiltinID::PropLocalCA => "local_ca",
        BuiltinID::PropTlsIdentity => "identity",
        _ => panic!("invalid tlskey property"),
    }
}
