# Authly

Authly is a flexible Attribute-based Access Control (ABAC) Identity and Access Management (IAM) solution with minimalist Service Mesh control plane and data plane capabilitites.

The Authly server relies on mTLS for service client authentication, and can provision such services with client certificates from a mesh-local Certificate Authority (CA), either manually, through a native Rust client ([`authly-client`](https://crates.io/crates/authly-client)) through its language bindings (TBA), or a minimalist sidecar proxy (TBA).

Attributes can be used to model roles, resources, actions and other concepts, and are configured through declarative TOML documents. Policies use attributes through a simple DSL.

## Table of Contents

- [Installation](#installation)
- [Quickstart](#quickstart)
- [Contributing](#contributing)
- [License](#license)

## Installation

Authly is available as an amd64/arm64 Docker image:

```bash
docker run ghcp.io/protojour/authly
```

It uses an embedded database and _can_ run independently, in principle. However, it is not intended to run directly exposed to the internet, and should have access to a secrets store. Refer to [Quickstart](#quickstart) for more complete examples.

## Quickstart

### Kubernetes example (recommended)

An example Kubernetes deployment is available in [`testfiles/k8s`](testfiles/k8s), which includes the Authly-compatible [Arx gateway](https://github.com/protojour/arx), the correct routing and setup for Authly to provision itself and an example service with mTLS, and uses the Kubernetes secret store for its core identity.

### Docker example

A minimal `docker compose` development example is available in [`testfiles/docker/docker-compose.yml`](testfiles/docker/docker-compose.yml).

## Contributing

...

## License

Authly is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPLv3) license. Contact us for commercial licensing options.
