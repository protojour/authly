use http::header::CONTENT_TYPE;
use hyper::body::Incoming;
use std::error::Error as StdError;

#[derive(Default)]
pub struct ProtocolRouter {
    routers: Vec<(Protocol, axum::Router)>,
}

impl ProtocolRouter {
    pub fn with_grpc(mut self, router: axum::Router) -> Self {
        self.routers.push((Protocol::Grpc, router));
        self
    }

    pub fn or_default(mut self, router: axum::Router) -> Self {
        self.routers.push((Protocol::Default, router));
        self
    }

    pub fn into_service(
        self,
    ) -> impl tower::Service<
        http::Request<Incoming>,
        Response = axum::response::Response,
        Future: 'static + Send,
        Error: Into<Box<dyn StdError + Send + Sync>>,
    > + Clone {
        let default = if self.routers.len() == 1 {
            0
        } else {
            self.routers
                .iter()
                .position(|(p, _)| matches!(p, Protocol::Default))
                .expect("no default router found")
        };
        let grpc = self
            .routers
            .iter()
            .position(|(p, _)| matches!(p, Protocol::Grpc));

        tower::steer::Steer::new(
            self.routers.into_iter().map(|(_, router)| router),
            move |req: &http::Request<Incoming>, _services: &[_]| {
                if req
                    .headers()
                    .get(CONTENT_TYPE)
                    .map(|content_type| content_type.as_bytes())
                    .filter(|content_type| content_type.starts_with(b"application/grpc"))
                    .is_some()
                {
                    grpc.unwrap_or(default)
                } else {
                    default
                }
            },
        )
    }
}

enum Protocol {
    Grpc,
    Default,
}
