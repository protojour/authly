use authly_common::proto::mandate_submission::{
    self as proto,
    authly_mandate_submission_server::{AuthlyMandateSubmission, AuthlyMandateSubmissionServer},
};
use rcgen::CertificateSigningRequestParams;
use rustls::pki_types::CertificateSigningRequestDer;
use tonic::{Request, Response};
use tracing::warn;

use crate::{authority_mandate::submission, AuthlyCtx};

pub struct AuthlyMandateSubmissionServerImpl {
    pub(crate) ctx: AuthlyCtx,
}

impl AuthlyMandateSubmissionServerImpl {
    pub fn into_service(self) -> AuthlyMandateSubmissionServer<Self> {
        AuthlyMandateSubmissionServer::new(self)
    }
}

#[tonic::async_trait]
impl AuthlyMandateSubmission for AuthlyMandateSubmissionServerImpl {
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

        let mut cert_chain = vec![proto::AuthlyCertificate {
            certifies_entity_id: certified_mandate.mandate_eid.to_bytes().to_vec(),
            signed_by_entity_id: self.ctx.instance.authly_eid().to_bytes().to_vec(),
            der: certified_mandate.certificate.der().to_vec(),
        }];

        // pass our local certificates to the mandate
        for authly_cert in self.ctx.instance.cert_chain() {
            cert_chain.push(proto::AuthlyCertificate {
                certifies_entity_id: authly_cert.certifies.to_bytes().to_vec(),
                signed_by_entity_id: authly_cert.signed_by.to_bytes().to_vec(),
                der: authly_cert.der.to_vec(),
            });
        }

        Ok(tonic::Response::new(proto::SubmissionResponse {
            mandate_entity_id: certified_mandate.mandate_eid.to_bytes().to_vec(),
            cert_chain,
        }))
    }
}
