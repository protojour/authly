use std::{collections::HashMap, fmt::Debug};

use aes_gcm_siv::{
    aead::{Aead, Nonce},
    Aes256GcmSiv, Key, KeyInit,
};
use anyhow::anyhow;
use authly_common::id::PropId;
use authly_db::{Db, DbError};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

use crate::{id::BuiltinProp, repo::crypto_repo, IsLeaderDb};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("crypto error: {0}")]
    Crypto(anyhow::Error),
}

#[derive(Clone)]
pub struct EncryptedDek {
    pub nonce: Nonce<Aes256GcmSiv>,
    pub ciph: Vec<u8>,
    pub created_at: time::OffsetDateTime,
}

/// The set of Data Encryption Keys used by authly
#[derive(Default, Debug)]
pub struct DecryptedDeks {
    deks: HashMap<PropId, AesKey>,
}

impl DecryptedDeks {
    pub const fn new(deks: HashMap<PropId, AesKey>) -> Self {
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
    pub encrypted: MasterVersion,
    pub key: AesKey,
}

impl DecryptedMaster {
    pub fn fake_for_test() -> Self {
        Self {
            encrypted: MasterVersion {
                version: b"fake for test".to_vec(),
                created_at: OffsetDateTime::now_utc(),
            },
            key: AesKey::new([42u8; 32].into()),
        }
    }
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
    pub const fn new(key: Key<Aes256GcmSiv>) -> Self {
        Self { key }
    }

    pub fn load(bytes: Zeroizing<Vec<u8>>) -> anyhow::Result<Self> {
        let key = Key::<Aes256GcmSiv>::from_exact_iter(bytes.iter().copied())
            .ok_or_else(|| anyhow!("invalid key length"))?;

        Ok(Self { key })
    }

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

impl Drop for AesKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub async fn gen_prop_deks(
    deps: &impl Db,
    decrypted_master: &DecryptedMaster,
    is_leader: IsLeaderDb,
) -> anyhow::Result<HashMap<PropId, AesKey>> {
    let old_encrypted_deks = crypto_repo::list_all_cr_prop_deks(deps).await?;
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
        crypto_repo::insert_cr_prop_deks(deps, new_encrypted_deks).await?;
    }

    Ok(decrypted_deks)
}

#[derive(Clone)]
pub struct EncryptedObjIdent {
    pub prop_id: PropId,
    pub fingerprint: [u8; 32],
    pub nonce: Nonce<Aes256GcmSiv>,
    pub ciph: Vec<u8>,
}

impl EncryptedObjIdent {
    pub fn encrypt(prop_id: PropId, value: &str, deks: &DecryptedDeks) -> anyhow::Result<Self> {
        let dek = deks.get(prop_id).map_err(CryptoError::Crypto)?;
        let fingerprint = dek.fingerprint(value.as_bytes());
        let nonce = random_nonce();
        let ciph = dek
            .aes()
            .encrypt(&nonce, value.as_bytes())
            .map_err(|err| CryptoError::Crypto(err.into()))?;

        Ok(Self {
            prop_id,
            fingerprint,
            nonce,
            ciph,
        })
    }
}

fn all_encrypted_props() -> impl Iterator<Item = BuiltinProp> {
    BuiltinProp::iter().filter(|id| id.is_encrypted())
}

pub fn random_nonce() -> Nonce<Aes256GcmSiv> {
    let mut nonce = *Nonce::<Aes256GcmSiv>::from_slice(&[0; 12]); // 96-bits; unique per message
    OsRng.fill_bytes(nonce.as_mut_slice());
    nonce
}
