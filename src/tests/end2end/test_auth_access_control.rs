#![allow(unused)]

use std::time::Instant;

use authly_client::AccessControl;
use authly_common::id::Eid;
use cookie::Cookie;
use hexhex::hex_literal;
use hyper::header::SET_COOKIE;
use reqwest::Identity;
use serde_json::{json, Value};
use tracing::info;

use super::{is_allowed, is_denied, ConnectionBuilder};

#[tokio::test]
#[ignore = "end2end"]
async fn user_auth_ok() -> anyhow::Result<()> {
    let web_client = ConnectionBuilder::for_testservice()?.http_client()?;

    let response: Value = web_client
        .post("https://localhost:1443/api/auth/authenticate")
        .json(&json!({
            "username": "testuser",
            "password": "secret",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    info!(?response, "user authenticated");
    Ok(())
}

#[tokio::test]
#[ignore = "end2end"]
async fn auth_session_cookie_to_access_token() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let conn_builder = ConnectionBuilder::for_testservice()?;
    let web_client = conn_builder.http_client()?;
    let authly_client = conn_builder.service_client().await?;

    let response = web_client
        .post("https://localhost:1443/api/auth/authenticate")
        .json(&json!({
            "username": "testuser",
            "password": "secret",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let mut session_cookie = Cookie::parse_encoded(
        response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();

    let start = Instant::now();

    let access_token = authly_client
        .get_access_token(session_cookie.value_trimmed())
        .await
        .unwrap();

    let elapsed = start.elapsed();

    println!("get_access_token took {elapsed:?}");

    assert_eq!(
        access_token.claims.authly.entity_id,
        hex_literal!("0fbcd73e1a884424a1615c3c3fdeebec").into()
    );
    assert_eq!(1, access_token.claims.authly.entity_attributes.len());

    // bad access control request (without resource attributes)
    {
        let outcome = authly_client
            .access_control_request()
            .access_token(access_token.clone())
            .evaluate()
            .await
            .unwrap();

        assert!(is_denied(outcome));
    }

    // access control request with unknown resource attribute fails
    {
        let Err(authly_client::Error::InvalidPropertyAttributeLabel) = authly_client
            .access_control_request()
            .resource_attribute(("fake", "bogus", "pomp"))
        else {
            panic!("incorrect error");
        };
    }

    // the testuser has role/ui:user so it may read ontology
    {
        let outcome = authly_client
            .access_control_request()
            .resource_attribute(("testservice", "ontology/action", "read"))?
            .access_token(access_token.clone())
            .evaluate()
            .await
            .unwrap();

        assert!(is_allowed(outcome));
    }

    // the testuser is not role/ui:admin so it may not deploy ontology
    {
        let outcome = authly_client
            .access_control_request()
            .resource_attribute(("testservice", "ontology/action", "deploy"))?
            .access_token(access_token.clone())
            .evaluate()
            .await
            .unwrap();

        assert!(is_denied(outcome));
    }

    Ok(())
}
