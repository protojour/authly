use std::{collections::HashMap, fmt::Debug};

use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit};
use anyhow::anyhow;
use authly_common::id::PropId;
use zeroize::{Zeroize, Zeroizing};

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
