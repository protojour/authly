use std::borrow::Cow;

use aes_gcm_siv::{
    aead::{Aead, Nonce},
    Aes256GcmSiv,
};
use authly_common::id::{AnyId, PropId};
use authly_db::{param::ToBlob, params, Db, DbResult, FromRow, Row};
use indoc::indoc;

use crate::{
    ctx::{GetDb, GetDecryptedDeks},
    encryption::{CryptoError, DecryptedDeks, EncryptedObjIdent},
};

impl EncryptedObjIdent {
    pub async fn insert<D: Db>(
        self,
        deps: &D,
        dir_key: impl Into<<D as Db>::Param>,
        obj_id: AnyId,
        now: i64,
    ) -> DbResult<()> {
        let (stmt, params) = self.insert_stmt::<D>(dir_key, obj_id, now);
        deps.execute(stmt, params).await?;
        Ok(())
    }

    pub fn insert_stmt<D: Db>(
        self,
        dir_key: impl Into<<D as Db>::Param>,
        obj_id: AnyId,
        now: i64,
    ) -> (Cow<'static, str>, Vec<<D as Db>::Param>) {
        (
            indoc! {
                "
                INSERT INTO obj_ident (dir_key, obj_id, prop_key, upd, fingerprint, nonce, ciph)
                VALUES ($1, $2, (SELECT key FROM prop WHERE id = $3), $4, $5, $6, $7)
                "
            }
            .into(),
            params!(
                dir_key,
                obj_id.to_blob(),
                self.prop_id.to_blob(),
                now,
                self.fingerprint.to_vec(),
                self.nonce.to_vec(),
                self.ciph
            ),
        )
    }

    pub async fn upsert<D: Db>(
        self,
        deps: &D,
        dir_key: impl Into<<D as Db>::Param>,
        obj_id: AnyId,
        now: i64,
    ) -> DbResult<()> {
        let (stmt, params) = self.upsert_stmt::<D>(dir_key, obj_id, now);
        deps.execute(stmt, params).await?;
        Ok(())
    }

    pub fn upsert_stmt<D: Db>(
        self,
        dir_key: impl Into<<D as Db>::Param>,
        obj_id: AnyId,
        now: i64,
    ) -> (Cow<'static, str>, Vec<<D as Db>::Param>) {
        (
            indoc! {
                "
                INSERT INTO obj_ident (dir_key, obj_id, prop_key, upd, fingerprint, nonce, ciph)
                VALUES ($1, $2, (SELECT key FROM prop WHERE id = $3), $4, $5, $6, $7)
                ON CONFLICT DO UPDATE SET
                    upd = $4,
                    fingerprint = $5,
                    nonce = $6,
                    ciph = $7
                "
            }
            .into(),
            params!(
                dir_key,
                obj_id.to_blob(),
                self.prop_id.to_blob(),
                now,
                self.fingerprint.to_vec(),
                self.nonce.to_vec(),
                self.ciph
            ),
        )
    }
}

pub async fn lookup_obj_ident(
    deps: &(impl GetDb + GetDecryptedDeks),
    prop_id: PropId,
    ident: &str,
) -> Result<Option<AnyId>, CryptoError> {
    struct TypedRow(AnyId);

    impl FromRow for TypedRow {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_id("obj_id"))
        }
    }

    let ident_fingerprint = {
        let deks = deps.get_decrypted_deks();
        let dek = deks.get(prop_id).map_err(CryptoError::Crypto)?;

        dek.fingerprint(ident.as_bytes())
    };

    let Some(row) = deps
        .get_db()
        .query_map_opt::<TypedRow>(
            indoc! {
                "
                SELECT obj_id FROM obj_ident WHERE prop_key = (SELECT key FROM prop WHERE id = $1) AND fingerprint = $2
                ",
            }
            .into(),
            params!(prop_id.to_blob(), ident_fingerprint.as_slice().to_blob()),
        )
        .await?
    else {
        return Ok(None);
    };

    Ok(Some(row.0))
}

pub async fn load_decrypt_obj_ident(
    deps: &impl Db,
    obj_id: AnyId,
    prop_id: PropId,
    deks: &DecryptedDeks,
) -> Result<Option<String>, CryptoError> {
    struct TypedRow {
        pub nonce: Nonce<Aes256GcmSiv>,
        pub ciph: Vec<u8>,
    }

    impl FromRow for TypedRow {
        fn from_row(row: &mut impl Row) -> Self {
            Self {
                nonce: row.get_blob_array("nonce").into(),
                ciph: row.get_blob("ciph"),
            }
        }
    }

    let Some(row) = deps
        .query_map_opt::<TypedRow>(
            "SELECT nonce, ciph FROM obj_ident WHERE obj_id = $1 AND prop_key = (SELECT key FROM prop WHERE id = $2)".into(),
            params!(obj_id.to_blob(), prop_id.to_blob()),
        )
        .await?
    else {
        return Ok(None);
    };

    let decrypted = deks
        .get(prop_id)
        .map_err(CryptoError::Crypto)?
        .aes()
        .decrypt(&row.nonce, row.ciph.as_ref())
        .map_err(|err| CryptoError::Crypto(err.into()))?;

    Ok(Some(
        String::from_utf8(decrypted).map_err(|err| CryptoError::Crypto(err.into()))?,
    ))
}
