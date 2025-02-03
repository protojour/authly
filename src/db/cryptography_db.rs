//! cryptography-oriented things stored in the DB (secret information is encrypted!)

use std::{borrow::Cow, collections::HashMap, str::FromStr, time::Duration};

use aes_gcm_siv::aead::Aead;
use anyhow::{anyhow, Context};
use authly_common::id::{Eid, PropId};
use authly_db::{param::AsParam, Db, DbError, FromRow, Row, TryFromRow};
use hiqlite::{params, Param, Params};
use indoc::indoc;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tracing::{debug, info};

use crate::{
    cert::{authly_ca, client_cert, key_pair},
    encryption::{random_nonce, DecryptedDeks, EncryptedDek, MasterVersion},
    id::BuiltinProp,
    instance::AuthlyId,
    tls::{AuthlyCert, AuthlyCertKind},
    AuthlyInstance, IsLeaderDb,
};

#[derive(Error, Debug)]
pub enum CrDbError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("crypto error: {0}")]
    Crypto(anyhow::Error),
}

impl FromRow for MasterVersion {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            version: row.get_blob("version"),
            created_at: row.get_datetime("created_at").unwrap(),
        }
    }
}

pub async fn load_cr_master_version(deps: &impl Db) -> Result<Option<MasterVersion>, CrDbError> {
    Ok(deps
        .query_map_opt(
            "SELECT version, created_at FROM cr_master_version".into(),
            params!(),
        )
        .await?)
}

pub async fn insert_cr_master_version(deps: &impl Db, ver: MasterVersion) -> Result<(), CrDbError> {
    deps.execute(
        "INSERT INTO cr_master_version (version, created_at) VALUES ($1, $2)".into(),
        params!(ver.version, ver.created_at.unix_timestamp()),
    )
    .await?;

    Ok(())
}

pub async fn list_all_cr_prop_deks(
    deps: &impl Db,
) -> Result<HashMap<BuiltinProp, EncryptedDek>, CrDbError> {
    struct Output(BuiltinProp, EncryptedDek);

    impl TryFromRow for Output {
        type Error = anyhow::Error;

        fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
            let prop_id: PropId = row.get_id("prop_id");
            let builtin_id = BuiltinProp::try_from(prop_id.to_uint() as u32)
                .map_err(|_| anyhow!("invalid builtin property"))?;

            Ok(Self(
                builtin_id,
                EncryptedDek {
                    nonce: row.get_blob_array("nonce").into(),
                    ciph: row.get_blob("ciph"),
                    created_at: row.get_datetime("created_at").unwrap(),
                },
            ))
        }
    }

    Ok(deps
        .query_filter_map(
            "SELECT prop_id, nonce, ciph, created_at FROM cr_prop_dek".into(),
            params!(),
        )
        .await?
        .into_iter()
        .map(|Output(id, dek)| (id, dek))
        .collect())
}

pub async fn insert_cr_prop_deks(
    deps: &impl Db,
    deks: HashMap<PropId, EncryptedDek>,
) -> Result<(), CrDbError> {
    for (id, dek) in deks {
        deps.execute(
            "INSERT INTO cr_prop_dek (prop_id, nonce, ciph, created_at) VALUES ($1, $2, $3, $4)"
                .into(),
            params!(
                id.as_param(),
                dek.nonce.to_vec(),
                dek.ciph,
                dek.created_at.unix_timestamp()
            ),
        )
        .await?;
    }

    Ok(())
}

/// Load the AuthlyInstance (identity and certificates)
///
/// If starting up for the first time, then self-signed CA and identity is generated.
/// These can be changed after the fact, after registering an authly authority for the first time.
pub async fn load_authly_instance(
    is_leader: IsLeaderDb,
    db: &impl Db,
    deks: &DecryptedDeks,
) -> Result<AuthlyInstance, CrDbError> {
    let authly_id = load_or_generate_authly_id(is_leader, db, deks).await?;
    let mut certs = load_certs(db).await?;

    let missing_certs = check_missing_certs(&authly_id, &certs);

    if !missing_certs.is_empty() {
        if is_leader.0 {
            for kind in missing_certs {
                match kind {
                    AuthlyCertKind::Ca => {
                        let certificate = authly_ca().self_signed(&authly_id.private_key).unwrap();
                        let cert = AuthlyCert {
                            kind: AuthlyCertKind::Ca,
                            certifies: authly_id.eid,
                            signed_by: authly_id.eid,
                            params: certificate.params().clone(),
                            der: certificate.der().clone(),
                        };

                        save_tls_cert(&cert, db).await?;
                        certs.push(cert);
                    }
                    AuthlyCertKind::Identity => {
                        let certificate = client_cert(
                            &authly_id.eid.to_string(),
                            time::Duration::days(365 * 100),
                        )
                        .self_signed(&authly_id.private_key)
                        .unwrap();
                        let cert = AuthlyCert {
                            kind: AuthlyCertKind::Identity,
                            certifies: authly_id.eid,
                            signed_by: authly_id.eid,
                            params: certificate.params().clone(),
                            der: certificate.der().clone(),
                        };

                        save_tls_cert(&cert, db).await?;
                        certs.push(cert);
                    }
                }
            }
        } else {
            loop {
                info!("waiting for leader to generate certificates");
                tokio::time::sleep(Duration::from_secs(1)).await;

                certs = load_certs(db).await?;
                if check_missing_certs(&authly_id, &certs).is_empty() {
                    break;
                }
            }
        }
    }

    Ok(AuthlyInstance::new(authly_id, certs))
}

async fn load_or_generate_authly_id(
    is_leader: IsLeaderDb,
    db: &impl Db,
    deks: &DecryptedDeks,
) -> Result<AuthlyId, CrDbError> {
    match try_load_authly_id(db, deks).await? {
        Some(authly_id) => Ok(authly_id),
        None => {
            if is_leader.0 {
                let eid = Eid::random();
                let private_key = key_pair();

                debug!("initializing new authly ID");

                save_instance(eid, &private_key, db, deks).await?;

                Ok(AuthlyId { eid, private_key })
            } else {
                loop {
                    info!("waiting for leader to generate Authly ID");
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    if let Some(local_ca) = try_load_authly_id(db, deks).await? {
                        return Ok(local_ca);
                    }
                }
            }
        }
    }
}

async fn try_load_authly_id(
    deps: &impl Db,
    deks: &DecryptedDeks,
) -> Result<Option<AuthlyId>, CrDbError> {
    struct Output(Eid, [u8; 12], Vec<u8>);

    impl FromRow for Output {
        fn from_row(row: &mut impl Row) -> Self {
            Self(
                row.get_id("eid"),
                row.get_blob_array("private_key_nonce"),
                row.get_blob("private_key_ciph"),
            )
        }
    }

    let Some(Output(eid, nonce, private_key_ciph)) = deps
        .query_map_opt(
            "SELECT eid, private_key_nonce, private_key_ciph FROM authly_instance".into(),
            params!(),
        )
        .await?
    else {
        return Ok(None);
    };

    let dek = deks
        .get(BuiltinProp::AuthlyInstance.into())
        .map_err(CrDbError::Crypto)?;

    let private_key_plaintext = dek
        .aes()
        .decrypt(&nonce.into(), private_key_ciph.as_ref())
        .context("FATAL: Encryption key has changed, unable to decrypt private key")
        .map_err(CrDbError::Crypto)?;

    let private_key_der = PrivateKeyDer::try_from(private_key_plaintext)
        .map_err(|msg| CrDbError::Crypto(anyhow!("private key: {msg}")))?;

    Ok(Some(AuthlyId {
        eid,
        private_key: KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_ECDSA_P256_SHA256)?,
    }))
}

pub async fn save_instance(
    eid: Eid,
    private_key: &KeyPair,
    db: &impl Db,
    deks: &DecryptedDeks,
) -> Result<(), CrDbError> {
    let private_key_der = private_key.serialize_der();

    let dek = deks
        .get(BuiltinProp::AuthlyInstance.into())
        .map_err(CrDbError::Crypto)?;
    let nonce = random_nonce();
    let key_ciph = dek
        .aes()
        .encrypt(&nonce, private_key_der.as_ref())
        .map_err(|err| CrDbError::Crypto(err.into()))?;

    db.execute(
        indoc! {
            "
            INSERT INTO authly_instance (key, eid, private_key_nonce, private_key_ciph)
            VALUES ('self', $1, $2, $3)
            ON CONFLICT DO UPDATE SET eid = $1
            "
        }
        .into(),
        params!(eid.as_param(), nonce.to_vec(), key_ciph),
    )
    .await?;

    Ok(())
}

impl TryFromRow for AuthlyCert {
    type Error = anyhow::Error;

    fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
        let kind = row.get_text("kind");
        let Ok(kind) = AuthlyCertKind::from_str(&kind) else {
            return Err(anyhow!("invalid cert kind: {kind}"));
        };
        let cert_der = CertificateDer::from(row.get_blob("der"));

        Ok(Self {
            kind,
            certifies: row.get_id("certifies_eid"),
            signed_by: row.get_id("signed_by_eid"),
            params: CertificateParams::from_ca_cert_der(&cert_der)?,
            der: cert_der,
        })
    }
}

async fn load_certs(db: &impl Db) -> Result<Vec<AuthlyCert>, CrDbError> {
    Ok(db
        .query_filter_map(
            "SELECT kind, certifies_eid, signed_by_eid, der FROM tls_cert".into(),
            params!(),
        )
        .await?)
}

fn check_missing_certs(authly_id: &AuthlyId, certs: &[AuthlyCert]) -> Vec<AuthlyCertKind> {
    let mut missing = vec![];

    if !certs
        .iter()
        .any(|cert| matches!(cert.kind, AuthlyCertKind::Ca) && cert.certifies == authly_id.eid)
    {
        missing.push(AuthlyCertKind::Ca);
    }

    if !certs.iter().any(|cert| {
        matches!(cert.kind, AuthlyCertKind::Identity) && cert.certifies == authly_id.eid
    }) {
        missing.push(AuthlyCertKind::Identity);
    }

    missing
}

async fn save_tls_cert(cert: &AuthlyCert, db: &impl Db) -> Result<(), CrDbError> {
    let (sql, params) = save_tls_cert_sql(cert);
    db.execute(sql, params).await?;

    Ok(())
}

pub fn save_tls_cert_sql(cert: &AuthlyCert) -> (Cow<'static, str>, Params) {
    let cert_der = cert.der.to_vec();
    let now = time::OffsetDateTime::now_utc();
    let expires = cert.params.not_after;
    (
        indoc! {
            "
            INSERT INTO tls_cert (kind, certifies_eid, signed_by_eid, created_at, expires_at, der)
            VALUES ($1, $2, $3, $4, $5, $6)
            "
        }
        .into(),
        params!(
            cert.kind.to_string(),
            cert.certifies.as_param(),
            cert.signed_by.as_param(),
            now.unix_timestamp(),
            expires.unix_timestamp(),
            cert_der
        ),
    )
}

impl From<hiqlite::Error> for CrDbError {
    fn from(value: hiqlite::Error) -> Self {
        Self::Db(DbError::Hiqlite(value))
    }
}

impl From<rcgen::Error> for CrDbError {
    fn from(value: rcgen::Error) -> Self {
        Self::Crypto(value.into())
    }
}
