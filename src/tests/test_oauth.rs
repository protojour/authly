use authly_common::id::DirectoryId;
use authly_db::Db;
use authly_domain::{
    ctx::{GetDb, GetDecryptedDeks},
    directory::{DirKey, OAuthDirectory, PersonaDirectory},
    id::BuiltinProp,
};
use axum::extract::{Path, Query, State};
use itertools::Itertools;
use rand::{rngs::OsRng, Rng};
use serde_json::json;
use wiremock::{
    matchers::{header, method, path, query_param},
    Mock, ResponseTemplate,
};

use crate::{
    db::{
        cryptography_db::EncryptedObjIdent,
        oauth_db::{
            oauth_upsert_params, oauth_upsert_secret_stmt, oauth_upsert_stmt,
            upsert_oauth_directory_stmt,
        },
        object_db,
    },
    directory::load_persona_directories,
    persona_directory::{self, ForeignPersona},
    test_support::TestCtx,
    util::base_uri::ProxiedBaseUri,
    web::auth::oauth::OAuthState,
};

fn random_oauth(dir_id: DirectoryId, dir_key: DirKey) -> OAuthDirectory {
    fn rnd() -> String {
        let mut bytes = [0; 8];
        OsRng.fill(bytes.as_mut_slice());
        hexhex::hex(bytes).to_string()
    }

    OAuthDirectory {
        dir_key,
        dir_id,
        client_id: rnd(),
        client_secret: "".to_string(),
        auth_url: rnd(),
        auth_req_scope: Some(rnd()),
        auth_req_client_id_field: Some(rnd()),
        auth_req_nonce_field: Some(rnd()),
        auth_res_code_path: Some(rnd()),
        token_url: rnd(),
        token_req_client_id_field: Some(rnd()),
        token_req_client_secret_field: Some(rnd()),
        token_req_code_field: Some(rnd()),
        token_req_callback_url_field: Some(rnd()),
        token_res_access_token_field: Some(rnd()),
        user_url: rnd(),
        user_res_id_path: Some(rnd()),
        user_res_email_path: Some(rnd()),
    }
}

fn github_like(
    dir_id: DirectoryId,
    dir_key: DirKey,
    web_base_url: &str,
    api_base_url: &str,
) -> OAuthDirectory {
    OAuthDirectory {
        dir_key,
        dir_id,
        client_id: "123".to_string(),
        client_secret: "456".to_string(),
        auth_url: format!("{web_base_url}/login/oauth/authorize"),
        auth_req_scope: Some("user:email".to_string()),
        auth_req_client_id_field: Some("client_id".to_string()),
        auth_req_nonce_field: Some("state".to_string()),
        auth_res_code_path: Some("code".to_string()),
        token_url: format!("{web_base_url}/login/oauth/access_token"),
        token_req_client_id_field: Some("client_id".to_string()),
        token_req_client_secret_field: Some("client_secret".to_string()),
        token_req_code_field: Some("code".to_string()),
        token_req_callback_url_field: Some("redirect_uri".to_string()),
        token_res_access_token_field: Some("access_token".to_string()),
        user_url: format!("{api_base_url}/user"),
        user_res_id_path: Some("id".to_string()),
        user_res_email_path: Some("email".to_string()),
    }
}

#[tokio::test]
async fn test_insert_update_list_oauth_directory() {
    let ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;

    let dir_id = DirectoryId::random();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    let dir_key = {
        let (sql, params) = upsert_oauth_directory_stmt(None, dir_id, "buksehub");

        // insert and upsert
        ctx.get_db()
            .query_map_opt::<DirKey>(sql.clone(), params.clone())
            .await
            .unwrap();
        ctx.get_db()
            .query_map_opt::<DirKey>(sql, params)
            .await
            .unwrap()
            .unwrap()
    };

    let oauth_a = random_oauth(dir_id, dir_key);

    {
        let (sql, params) = oauth_upsert_secret_stmt::<<TestCtx as GetDb>::Db>(
            &oauth_a,
            dir_key,
            now,
            &ctx.get_decrypted_deks(),
        )
        .unwrap();

        ctx.get_db().execute(sql, params).await.unwrap();
    }

    ctx.get_db()
        .execute(oauth_upsert_stmt(), oauth_upsert_params(oauth_a, now))
        .await
        .unwrap();

    let oauth_b = random_oauth(dir_id, dir_key);

    ctx.get_db()
        .execute(
            oauth_upsert_stmt(),
            oauth_upsert_params(oauth_b.clone(), now),
        )
        .await
        .unwrap();

    let mut dirs = load_persona_directories(ctx.get_db(), &ctx.load_decrypted_deks())
        .await
        .unwrap();

    assert_eq!(1, dirs.len());
    let PersonaDirectory::OAuth(oauth) = dirs.swap_remove("buksehub").unwrap();

    assert_eq!(oauth, oauth_b);
}

#[test_log::test(tokio::test)]
async fn test_upsert_persona_link() {
    let ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;
    let dir_id = DirectoryId::random();

    let dir_key = {
        let (sql, params) = upsert_oauth_directory_stmt(None, dir_id, "buksehub");

        // insert and upsert
        ctx.get_db()
            .query_map_opt::<DirKey>(sql.clone(), params.clone())
            .await
            .unwrap();
        ctx.get_db()
            .query_map_opt::<DirKey>(sql, params)
            .await
            .unwrap()
            .unwrap()
    };

    let foreign_id = b"foobar";

    let (persona_id1, did_insert1) = persona_directory::link_foreign_persona(
        &ctx,
        dir_key,
        ForeignPersona {
            foreign_id: foreign_id.to_vec(),
            email: "oldmail@mail.com".to_string(),
        },
    )
    .await
    .unwrap();

    assert!(did_insert1.0);

    // NB: currently suboptimal because one entity cannot have more than one email address,
    // and there can't be any automatic transition because entity idents (e.g. email) are not keyed by directory, they are "global".
    // Find a way to fix the model.
    // Maybe the OAuth that _created_ the entity may change the global email.
    let (persona_id2, did_insert2) = persona_directory::link_foreign_persona(
        &ctx,
        dir_key,
        ForeignPersona {
            foreign_id: foreign_id.to_vec(),
            email: "newmail@mail.com".to_string(),
        },
    )
    .await
    .unwrap();

    assert!(!did_insert2.0);

    assert_eq!(
        persona_id1, persona_id2,
        "these refer to the same persona because the foreign_id is the same"
    );

    {
        let email = EncryptedObjIdent::encrypt(
            BuiltinProp::Email.into(),
            "newmail@mail.com",
            &ctx.get_decrypted_deks(),
        )
        .unwrap();
        let entity_id = object_db::find_obj_id_by_ident_fingerprint(
            ctx.get_db(),
            BuiltinProp::Email.into(),
            &email.fingerprint,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(entity_id, persona_id2.upcast());
    }
}

#[test_log::test(tokio::test)]
async fn test_upsert_persona_link_email_disambiguator() {
    let ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;
    let dir_a = DirectoryId::random();
    let dir_b = DirectoryId::random();
    let mut dir_keys = vec![];

    for (dir_id, label) in [dir_a, dir_b]
        .iter()
        .copied()
        .zip(["buksehub", "stillongshub"])
    {
        let (sql, params) = upsert_oauth_directory_stmt(None, dir_id, label);
        dir_keys.push(
            ctx.get_db()
                .query_map_opt::<DirKey>(sql.clone(), params.clone())
                .await
                .unwrap()
                .unwrap(),
        );
    }

    let [dir_key_a, dir_key_b] = dir_keys.into_iter().collect_array().unwrap();

    let shared_email = "addr@mail.com";

    let (persona_id1, _) = persona_directory::link_foreign_persona(
        &ctx,
        dir_key_a,
        ForeignPersona {
            foreign_id: b"foreign_a".to_vec(),
            email: shared_email.to_string(),
        },
    )
    .await
    .unwrap();

    let (persona_id2, _) = persona_directory::link_foreign_persona(
        &ctx,
        dir_key_b,
        ForeignPersona {
            foreign_id: b"foreign_b".to_vec(),
            email: shared_email.to_string(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        persona_id1, persona_id2,
        "these refer to the same persona because of a shared email address in two different persona directories"
    );
}

#[test_log::test(tokio::test)]
async fn test_callback_github_like() {
    let dir_id = DirectoryId::random();
    let code = "c0d3";
    let hubmock = wiremock::MockServer::start().await;

    let ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;

    let dir_key = {
        let (sql, params) = upsert_oauth_directory_stmt(None, dir_id, "buksehub");
        ctx.get_db()
            .query_map_opt::<DirKey>(sql.clone(), params.clone())
            .await
            .unwrap()
            .unwrap()
    };

    let oauth = github_like(dir_id, dir_key, &hubmock.uri(), &hubmock.uri());
    let ctx = ctx.with_persona_directory("buksehub", PersonaDirectory::OAuth(oauth));

    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(query_param("client_id", "123"))
        .and(query_param("client_secret", "456"))
        .and(query_param("code", code))
        .and(query_param(
            "redirect_uri",
            "http://localhost/auth/oauth/buksehub/callback",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
            "scope": "user:email",
            "token_type": "bearer"
        })))
        .mount(&hubmock)
        .await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header(
            "authorization",
            "Bearer gho_16C7e42F292c6912E7710c838347Ae178B4a",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "email": "user@users.com",
        })))
        .mount(&hubmock)
        .await;

    let _result = crate::web::auth::oauth::oauth_callback(
        State(OAuthState(ctx)),
        ProxiedBaseUri("http://localhost".parse().unwrap()),
        Path("buksehub".to_string()),
        Query([("code".to_string(), code.to_string())].into()),
    )
    .await
    .unwrap();
}
