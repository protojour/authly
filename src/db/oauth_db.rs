use std::borrow::Cow;

use authly_common::id::DirectoryId;
use authly_db::{param::ToBlob, params, Db, DbResult, FromRow, Params};
use authly_domain::{
    directory::{DirKey, OAuthDirectory},
    encryption::{CryptoError, DecryptedDeks, EncryptedObjIdent},
    id::BuiltinProp,
};
use indoc::indoc;

pub fn upsert_oauth_directory_stmt<D: Db>(
    parent_key: Option<DirKey>,
    dir_id: DirectoryId,
    label: &str,
) -> (Cow<'static, str>, Params<D>) {
    (
        indoc! {
            "
            INSERT INTO directory (parent_key, id, kind, url, hash, label)
            VALUES ($1, $2, 'persona', $3, $4, $5)
            ON CONFLICT DO UPDATE SET url = $3, hash = $4, label = $5
            RETURNING key
            "
        }
        .into(),
        params!(
            parent_key.map(|key| key.0),
            dir_id.to_blob(),
            "",
            vec![0u8; 32],
            label
        ),
    )
}

pub struct OAuthRow(pub OAuthDirectory);

impl FromRow for OAuthRow {
    fn from_row(row: &mut impl authly_db::Row) -> Self {
        Self(OAuthDirectory {
            dir_key: DirKey(row.get_int("dir_key")),
            dir_id: row.get_id("dir_id"),
            client_id: row.get_text("client_id"),
            // Client secret is loaded from separate table
            client_secret: "".to_string(),
            auth_url: row.get_text("auth_url"),
            auth_req_scope: row.get_opt_text("auth_req_scope"),
            auth_req_client_id_field: row.get_opt_text("auth_req_client_id_field"),
            auth_req_nonce_field: row.get_opt_text("auth_req_nonce_field"),
            auth_res_code_path: row.get_opt_text("auth_res_code_path"),
            token_url: row.get_text("token_url"),
            token_req_client_id_field: row.get_opt_text("token_req_client_id_field"),
            token_req_client_secret_field: row.get_opt_text("token_req_client_secret_field"),
            token_req_code_field: row.get_opt_text("token_req_code_field"),
            token_req_callback_url_field: row.get_opt_text("token_req_callback_url_field"),
            token_res_access_token_field: row.get_opt_text("token_res_access_token_field"),
            user_url: row.get_text("user_url"),
            user_res_id_path: row.get_opt_text("user_res_id_path"),
            user_res_email_path: row.get_opt_text("user_res_email_path"),
        })
    }
}

pub async fn oauth_query(deps: &impl Db) -> DbResult<Vec<OAuthRow>> {
    deps.query_map(
        "SELECT dir_oauth.*, directory.id AS dir_id FROM dir_oauth JOIN directory".into(),
        params!(),
    )
    .await
}

pub fn oauth_upsert_stmt() -> Cow<'static, str> {
    indoc! {
        "
        INSERT INTO dir_oauth (
            dir_key, upd, client_id,
            auth_url, auth_req_scope, auth_req_client_id_field, auth_req_nonce_field, auth_res_code_path,
            token_url, token_req_client_id_field, token_req_client_secret_field, token_req_code_field, token_req_callback_url_field, token_res_access_token_field,
            user_url, user_res_id_path, user_res_email_path
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
        ON CONFLICT DO UPDATE SET
            upd = $2,
            client_id = $3,
            auth_url = $4,
            auth_req_scope = $5,
            auth_req_client_id_field = $6,
            auth_req_nonce_field = $7,
            auth_res_code_path = $8,
            token_url = $9,
            token_req_client_id_field = $10,
            token_req_client_secret_field = $11,
            token_req_code_field = $12,
            token_req_callback_url_field = $13,
            token_res_access_token_field = $14,
            user_url = $15,
            user_res_id_path = $16,
            user_res_email_path = $17
        "
    }
    .into()
}

pub fn oauth_upsert_params<D: Db>(dir: OAuthDirectory, now: i64) -> Params<D> {
    params!(
        dir.dir_key.0,
        now,
        dir.client_id,
        dir.auth_url,
        dir.auth_req_scope,
        dir.auth_req_client_id_field,
        dir.auth_req_nonce_field,
        dir.auth_res_code_path,
        dir.token_url,
        dir.token_req_client_id_field,
        dir.token_req_client_secret_field,
        dir.token_req_code_field,
        dir.token_req_callback_url_field,
        dir.token_res_access_token_field,
        dir.user_url,
        dir.user_res_id_path,
        dir.user_res_email_path
    )
}

pub fn oauth_upsert_secret_stmt<D: Db>(
    dir: &OAuthDirectory,
    parent_dir_key: DirKey,
    now: i64,
    deks: &DecryptedDeks,
) -> Result<(Cow<'static, str>, Vec<<D as Db>::Param>), CryptoError> {
    Ok(EncryptedObjIdent::encrypt(
        BuiltinProp::OAuthClientSecret.into(),
        &dir.client_secret,
        deks,
    )
    .map_err(CryptoError::Crypto)?
    .upsert_stmt::<D>(parent_dir_key.0, dir.dir_id.upcast(), now))
}
