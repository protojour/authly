# Getting started

Authly's security model depends on a few core principles:

- Authly should not run directly exposed to the internet, as it expects mTLS for all connections. External clients should reach it through a gateway, which is provisioned by Authly.
- Other service clients are provisioned the same way, they are registered with Authly, and the client certificate is used as authentication.
- Authly's embedded database uses encryption-at-rest, and the master encryption key needs to be stored externally (and safely) in order to decrypt its data.

As a result, Authly requires a minimum set of key components to run:

- An Authly-compatible gateway using the [`authly-client`](https://crates.io/crates/authly-client) Rust library, such as [Arx](https://github.com/protojour/arx).
- Service clients using the [`authly-client`](https://crates.io/crates/authly-client) Rust library, either directly, through language bindings (TBA) or as a minimal sidecar proxy (TBA)
- A secure secrets store, we support [OpenBao](https://openbao.org/) (implemented), with pending support for [AWS Key Management Service](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html), [Azure Key Vault Standard](https://learn.microsoft.com/en-us/azure/key-vault/general/overview), and [Google Cloud Key Management](https://cloud.google.com/security/products/security-key-management).

Our [example Kubernetes setup](https://github.com/protojour/authly/tree/main/testfiles/k8s) features Authly itself, Arx, OpenBao and [an example service](https://github.com/protojour/authly/tree/main/crates/authly-testservice). A similar example is available for [docker compose](https://github.com/protojour/authly/tree/main/testfiles/docker/docker-compose.yml).

For Kubernetes installation, use our [Helm chart](https://github.com/protojour/authly/tree/main/pkg/helm/templates/Chart.yaml).
