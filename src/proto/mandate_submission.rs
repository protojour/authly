use authly_common::proto::mandate_submission::{
    self as proto,
    authly_mandate_submission_server::{AuthlyMandateSubmission, AuthlyMandateSubmissionServer},
};
use authly_db::GetDb;
use rcgen::CertificateSigningRequestParams;
use rustls::pki_types::CertificateSigningRequestDer;
use tonic::{Request, Response};
use tracing::warn;

use crate::{authority_mandate::submission, ctx::GetInstance};

pub struct AuthlyMandateSubmissionServerImpl<Ctx> {
    ctx: Ctx,
}

impl<Ctx> AuthlyMandateSubmissionServerImpl<Ctx> {
    pub fn new_service(ctx: Ctx) -> AuthlyMandateSubmissionServer<Self> {
        AuthlyMandateSubmissionServer::new(Self { ctx })
    }
}

#[tonic::async_trait]
impl<Ctx> AuthlyMandateSubmission for AuthlyMandateSubmissionServerImpl<Ctx>
where
    Ctx: GetDb + GetInstance + Send + Sync + 'static,
{
    /// Submit is tunneled through Authly Connect Secure
    async fn submit(
        &self,
        request: Request<proto::SubmissionRequest>,
    ) -> tonic::Result<Response<proto::SubmissionResponse>> {
        let req = request.into_inner();

        let csr_params = CertificateSigningRequestParams::from_der(
            &CertificateSigningRequestDer::from(req.identity_csr_der),
        )
        .map_err(|_err| tonic::Status::invalid_argument("invalid Certificate Signing Request"))?;

        let certified_mandate =
            submission::authority::authority_fulfill_submission(&self.ctx, &req.token, csr_params)
                .await
                .map_err(|err| {
                    warn!(?err, "submission error");
                    tonic::Status::internal("submission failed")
                })?;

        let instance = self.ctx.get_instance();

        // cert chain, start with Mandate's new local CA
        let mut ca_chain = vec![proto::AuthlyCertificate {
            certifies_entity_id: certified_mandate.mandate_eid.to_bytes().to_vec(),
            signed_by_entity_id: instance.authly_eid().to_bytes().to_vec(),
            der: certified_mandate.mandate_local_ca.der.to_vec(),
        }];

        // pass authority's local CA chain to the mandate
        for authly_cert in instance.ca_chain() {
            ca_chain.push(proto::AuthlyCertificate {
                certifies_entity_id: authly_cert.certifies.to_bytes().to_vec(),
                signed_by_entity_id: authly_cert.signed_by.to_bytes().to_vec(),
                der: authly_cert.der.to_vec(),
            });
        }

        Ok(tonic::Response::new(proto::SubmissionResponse {
            mandate_entity_id: certified_mandate.mandate_eid.to_bytes().to_vec(),
            mandate_identity_cert: Some(proto::AuthlyCertificate {
                certifies_entity_id: certified_mandate.mandate_eid.to_bytes().to_vec(),
                signed_by_entity_id: instance.authly_eid().to_bytes().to_vec(),
                der: certified_mandate.mandate_identity.der.to_vec(),
            }),
            ca_chain,
        }))
    }
}
