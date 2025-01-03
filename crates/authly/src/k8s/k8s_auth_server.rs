use std::sync::Arc;

use anyhow::anyhow;
use axum::{extract::State, response::IntoResponse, routing::post, Extension};
use axum_extra::headers::{authorization::Bearer, Authorization};
use http::{header::AUTHORIZATION, StatusCode};
use jsonwebtoken::{
    jwk::{AlgorithmParameters, JwkSet},
    DecodingKey, TokenData, Validation,
};
use rcgen::KeyPair;
use rustls::pki_types::PrivateKeyDer;
use tower_server::TlsConfigFactory;
use tracing::{error, info};

use crate::{cert::MakeSigningRequest, db::config_db::DynamicConfig, AuthlyCtx, EnvConfig};

const K8S_SERVICE_TOKENFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const K8S_SERVICE_CERTFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// TODO: Are these the same for all kubernetes clusters?
const K8S_CLUSTER_URL: &str = "https://kubernetes.default.svc.cluster.local";
const K8S_JWKS_URL: &str = "https://kubernetes.default.svc.cluster.local/openid/v1/jwks";

#[derive(Clone)]
struct K8SAuthServerState {
    ctx: AuthlyCtx,

    /// TODO: Should refetch this regularly (use ArcSwap)?
    jwk_set: Arc<JwkSet>,
}

#[derive(Debug)]
struct CsrError;

impl IntoResponse for CsrError {
    fn into_response(self) -> axum::response::Response {
        StatusCode::FORBIDDEN.into_response()
    }
}

mod claims {
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    pub struct KubernetesJwtClaims {
        #[expect(unused)]
        pub aud: Vec<String>,
        #[serde(rename = "kubernetes.io")]
        pub kubernetes_io: KubernetesIoJwtExt,
    }

    #[derive(Deserialize, Debug)]
    pub struct KubernetesIoJwtExt {
        #[expect(unused)]
        pub namespace: String,
        pub serviceaccount: K8sServiceAccount,
    }

    #[derive(Deserialize, Debug)]
    pub struct K8sServiceAccount {
        pub name: String,
    }
}

pub async fn spawn_k8s_auth_server(env_config: &EnvConfig, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let Some(port) = env_config.k8s_auth_server_port else {
        return Ok(());
    };

    let jwk_set = fetch_k8s_jwk_set().await?;
    let rustls_config_factory = rustls_server_config(env_config, &ctx.dynamic_config)?;

    let server = tower_server::Builder::new(format!("0.0.0.0:{port}").parse()?)
        .with_scheme(tower_server::Scheme::Https)
        .with_tls_config(rustls_config_factory)
        .with_cancellation_token(ctx.cancel.clone())
        .bind()
        .await?;

    tokio::spawn(
        server.serve(
            axum::Router::new()
                .route("/api/csr", post(csr_handler))
                .with_state(K8SAuthServerState {
                    ctx: ctx.clone(),
                    jwk_set: Arc::new(jwk_set),
                }),
        ),
    );

    Ok(())
}

async fn csr_handler(
    State(state): State<K8SAuthServerState>,
    bearer_authorization: Extension<Authorization<Bearer>>,
) -> Result<axum::response::Response, CsrError> {
    let token_data = verify_jwt(bearer_authorization.token(), &state.jwk_set)?;
    let service_account_name = token_data.claims.kubernetes_io.serviceaccount.name;

    Err(CsrError)
}

fn verify_jwt(
    token: &str,
    jwk_set: &JwkSet,
) -> Result<TokenData<claims::KubernetesJwtClaims>, CsrError> {
    let jwk = jwk_set.keys.first().ok_or_else(|| {
        error!("JwkSet contains no keys");
        CsrError
    })?;

    let mut validation = Validation::new(match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(_) => jsonwebtoken::Algorithm::ES256,
        AlgorithmParameters::RSA(_) => jsonwebtoken::Algorithm::RS256,
        _ => return Err(CsrError),
    });
    validation.set_audience(&[K8S_CLUSTER_URL]);

    let token_data = jsonwebtoken::decode::<claims::KubernetesJwtClaims>(
        &token,
        &DecodingKey::from_jwk(jwk).unwrap(),
        &validation,
    )
    .map_err(|err| {
        info!(?err, "token not verified");
        CsrError
    })?;

    Ok(token_data)
}

async fn fetch_k8s_jwk_set() -> anyhow::Result<JwkSet> {
    let service_account_token = std::fs::read_to_string(K8S_SERVICE_TOKENFILE)?;
    let k8s_ca = std::fs::read(K8S_SERVICE_CERTFILE)?;

    let jwk_set = reqwest::ClientBuilder::new()
        .add_root_certificate(reqwest::Certificate::from_pem(&k8s_ca)?)
        .build()?
        .get(K8S_JWKS_URL)
        .header(AUTHORIZATION, format!("Bearer {service_account_token}"))
        .send()
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;

    Ok(jwk_set)
}

fn rustls_server_config(
    env_config: &EnvConfig,
    dynamic_config: &DynamicConfig,
) -> anyhow::Result<TlsConfigFactory> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server_cert = dynamic_config
        .local_ca
        .sign(KeyPair::generate()?.server_cert(&env_config.hostname, time::Duration::days(365)));

    let server_private_key_der = PrivateKeyDer::try_from(server_cert.key.serialize_der())
        .map_err(|err| anyhow!("k8s auth server private key: {err}"))?;

    let mut config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert.der.clone()], server_private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);

    Ok(Arc::new(move || config.clone()))
}

#[test]
fn test_jwt_verification() {
    // token from /var/run/secrets/kubernetes.io/serviceaccount/token
    let test_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkFEVzkyekVRckJVaFphQ0FMR3BNZ19MQmxGX2RVZlpMUDZ2V1pOcnJwamcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxNzY3NDM2NDI2LCJpYXQiOjE3MzU5MDA0MjYsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJzaXR1IiwicG9kIjp7Im5hbWUiOiJtZW1vcmlhbS1wb3BzLTY3Njk5ZjljYi1obmZ3ZCIsInVpZCI6IjI3NDFjYjA2LTM2MTQtNDMwMy1hNWU1LWE3NDA1MjNjOWNiOSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoibWVtb3JpYW0tcG9wcyIsInVpZCI6ImYyNWE4YzM2LTYxYjgtNDMxZS04Y2E4LWFmMGIyMzZhOGU5MCJ9LCJ3YXJuYWZ0ZXIiOjE3MzU5MDQwMzN9LCJuYmYiOjE3MzU5MDA0MjYsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpzaXR1Om1lbW9yaWFtLXBvcHMifQ.uxCbjNjz84-rvAk6WZglyblYAQ8GXMV-6BSrAWPkDclWrvQZb8dpzoVC1FNERYi69_i3IlbnbPf0f7RFAcaj_DE0MF-229KSrNDAC-C5lslAe8ydglmu4F2IHYUta3UYWVJYo-_TUWnj7Me5wVnORQjkLa6tAbHw5_cBfk3DlZaIakcp6iUHQSQco22O-iPamVMxIFdfM1nYM3SyD-L8XapHb8SE0wA9iNmLXKTRmpPbfJYfJeKU2gpc_XW4PvMYceU4bSzYjJP8X_D_U_Ug_g8u-vqNiVhIHTkZYTnySM32kDOQu7h3dnkjqPw5RRKCqulGgcZ14c8IgYlGrjhVCg";
    // jwks from https://kubernetes.default.svc.cluster.local/openid/v1/jwks
    let k8s_jwks = serde_json::json!({
        "keys": [{
            "use": "sig",
            "kty": "RSA",
            "kid": "ADW92zEQrBUhZaCALGpMg_LBlF_dUfZLP6vWZNrrpjg",
            "alg": "RS256",
            "n": "1T0db0fJVbIeywP9NXPKCNqBJubqiM9Z0lkK4PydjLlZO_8beW6LQyHHgQhboZ4FlN9Xo5KWqPhkkZ2TJx6QecCHIUaecCCKObah7uHiAqTnXMRuXPKEmiz_W7oVp9aUZda_0RlZL8s2igUlvB8gCT78Gdz_abIjoy5ZDKuw2R_fGK1kvOuhLHhEMhMG_xi2vcf0m4Lt12X0k8ULR-J0PfedPCNPQdDg6lZAL26vvNVG6YunkaF-N4lbHAqPVJn48kVlG2uSN1sfQdkGButdqCRMLJVs9xojdQXwLkVeoJNZp8nv7i_sP4QtvNlLICD-QgiXRDhBew4LOnlnZLTm6Q",
            "e": "AQAB"
    }]});

    let jwk_set = serde_json::from_value(k8s_jwks).unwrap();
    let token_data = verify_jwt(test_token, &jwk_set).unwrap();

    assert_eq!(
        token_data.claims.kubernetes_io.serviceaccount.name,
        "memoriam-pops"
    );
}
