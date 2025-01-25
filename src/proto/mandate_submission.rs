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

        let mandate_certificate =
            submission::authority::authority_fulfill_submission(&self.ctx, &req.token, csr_params)
                .await
                .map_err(|err| {
                    warn!(?err, "submission error");
                    tonic::Status::internal("submission failed")
                })?;

        Ok(tonic::Response::new(proto::SubmissionResponse {
            authority_ca: self.ctx.tls_params.local_ca.der.to_vec(),
            mandate_identity_cert_der: mandate_certificate.der().to_vec(),
        }))
    }
}
