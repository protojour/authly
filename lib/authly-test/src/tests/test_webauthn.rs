use authly_common::id::PersonaId;
use authly_domain::{
    ctx::GetDb,
    repo::webauthn_repo,
    webauthn::{self, Webauthn, WebauthnBuilder},
};
use hexhex::hex_literal;
use http::Uri;
use reqwest::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::{softtoken::SoftToken, AuthenticatorBackend};

use crate::{test_ctx::TestCtx, util::compile_and_apply_doc_dir};

const TIMEOUT_MS: u32 = 1000;

async fn test_ctx_with_webauthn(webauthn: Webauthn) -> TestCtx {
    TestCtx::new()
        .inmemory_db()
        .await
        .supreme_instance()
        .await
        .with_webauthn(webauthn)
}

fn webauthn_localhost() -> Webauthn {
    WebauthnBuilder::new("localhost", &localhost())
        .unwrap()
        .build()
        .unwrap()
}

fn localhost() -> Url {
    "http://localhost".parse().unwrap()
}

fn localhost_uri() -> Uri {
    "http://localhost".parse().unwrap()
}

fn new_soft_token() -> SoftToken {
    let falsify_uv = true;
    SoftToken::new(falsify_uv).unwrap().0
}

const TESTUSER: &str = "testuser";
const TESTUSER_ID: PersonaId =
    PersonaId::from_raw_array(hex_literal!("0fbcd73e1a884424a1615c3c3fdeebec"));

#[test_log::test(tokio::test)]
async fn test_webauthn_happy_path() {
    let ctx = test_ctx_with_webauthn(webauthn_localhost()).await;
    compile_and_apply_doc_dir("../../examples/demo".into(), &ctx)
        .await
        .unwrap();

    let mut token = new_soft_token();
    // the username can be whatever:
    register_token(TESTUSER_ID, &mut token, &ctx).await;

    let login_session_id = Uuid::new_v4();

    let (persona_id, session) = {
        let auth_challenge = webauthn::webauthn_start_authentication(
            &ctx,
            &localhost_uri(),
            login_session_id,
            TESTUSER,
        )
        .await
        .unwrap();

        let credential = token
            .perform_auth(localhost(), auth_challenge.public_key, TIMEOUT_MS)
            .unwrap();

        webauthn::webauthn_finish_authentication(
            &ctx,
            &localhost_uri(),
            login_session_id,
            credential,
        )
        .await
        .unwrap()
    };

    assert_eq!(persona_id, TESTUSER_ID);
    assert_eq!(session.eid, TESTUSER_ID.upcast());

    // test update_last_used
    let passkey_row = webauthn_repo::list_passkeys_by_entity_id(ctx.get_db(), persona_id)
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    webauthn_repo::update_passkey_last_used(
        ctx.get_db(),
        persona_id,
        passkey_row.passkey.cred_id(),
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
}

#[test_log::test(tokio::test)]
async fn test_webauthn_invalid_username() {
    let ctx = test_ctx_with_webauthn(webauthn_localhost()).await;
    compile_and_apply_doc_dir("../../examples/demo".into(), &ctx)
        .await
        .unwrap();

    let mut token = new_soft_token();
    // the username can be whatever:
    register_token(TESTUSER_ID, &mut token, &ctx).await;

    let error = {
        let auth_challenge = webauthn::webauthn_start_authentication(
            &ctx,
            &localhost_uri(),
            Uuid::new_v4(),
            "username.incorrect",
        )
        .await
        .unwrap();

        token
            .perform_auth(localhost(), auth_challenge.public_key, TIMEOUT_MS)
            .unwrap_err()
    };

    assert_eq!(
        "Internal",
        format!("{error:?}"),
        "the error message is bad, but proves login failed"
    );
}

#[test_log::test(tokio::test)]
async fn test_webauthn_unregistered_token() {
    let ctx = test_ctx_with_webauthn(webauthn_localhost()).await;
    compile_and_apply_doc_dir("../../examples/demo".into(), &ctx)
        .await
        .unwrap();

    let auth_challenge =
        webauthn::webauthn_start_authentication(&ctx, &localhost_uri(), Uuid::new_v4(), TESTUSER)
            .await
            .unwrap();

    let mut token = new_soft_token();
    let error = token
        .perform_auth(localhost(), auth_challenge.public_key, TIMEOUT_MS)
        .unwrap_err();

    assert_eq!(
        "Internal",
        format!("{error:?}"),
        "the error message is bad, but proves login failed"
    );
}

async fn register_token(persona_id: PersonaId, token: &mut SoftToken, ctx: &TestCtx) {
    let reg_challenge = webauthn::webauthn_start_registration(ctx, &localhost_uri(), persona_id)
        .await
        .unwrap();

    let credential = token
        .perform_register(localhost(), reg_challenge.public_key, TIMEOUT_MS)
        .unwrap();

    webauthn::webauthn_finish_registration(ctx, &localhost_uri(), persona_id, credential)
        .await
        .unwrap();
}
