# Authly

Authly is a flexible Attribute-based Access Control (ABAC) Identity and Access Management (IAM) solution with minimalist Service Mesh control plane and data plane capabilitites (see [Security features](#security-features)).

Attributes can be used to model roles, resources, actions and other IAM concepts, and are configured through sequentially applied, declarative TOML documents (see [`examples/`](examples/)). Policies use these attributes through a simple DSL.

## Table of Contents

- [Installation](#installation)
- [Quickstart](#quickstart)
- [Security features](#security-features)
- [Feature roadmap](#feature-roadmap)
- [License](#license)

## Installation

Authly is available as a multi-arch (amd64/arm64) Docker image:

```bash
docker run ghcp.io/protojour/authly
```

It uses an embedded database and _can_ run independently, _in principle_. However, it is not intended to run directly exposed to the internet, and should have access to a secrets store. Refer to [Quickstart](#quickstart) for more complete examples.

## Quickstart

### Kubernetes example (recommended)

An example Kubernetes deployment is available in [`testfiles/k8s`](testfiles/k8s), which includes the Authly-compatible [Arx gateway](https://github.com/protojour/arx), a [Platform Abstraction Layer](https://github.com/protojour/authly-pal) for secrets, the correct routing and setup for Authly to provision an example service with mTLS, and uses the Kubernetes Secrets for its core identity.

### Docker example

A minimal `docker compose` development example is available in [`testfiles/docker/docker-compose.yml`](testfiles/docker/docker-compose.yml).

## Security features

The Authly server relies on mTLS for service client authentication, and can provision such services with client certificates from a (mesh-local or global) Certificate Authority, either manually (CLI commands), through a native [Rust client](https://crates.io/crates/authly-client), through its language bindings (TBA), or a minimalist sidecar proxy (TBA).

It uses an embedded [`hiqlite`](https://github.com/sebadob/hiqlite) database with envelope encrypted user data for encryption-at-rest.

Authly is not yet audited. We invite anyone to examine or critique its security model and report any vulnerabilities.

## Feature roadmap

Authly is beta software, currently with a minimal feature set, but several high-level features are planned:

- [ ] Federation and authority/mandate relations
- [ ] `authly-client` language bindings
- [ ] `authly-client`-based minimalist sidecar proxy
- [ ] Improved login UI
- [ ] User registration and recovery
- [ ] SMTP email support
- [ ] OATH TOTP support for authenticator apps
- [ ] OATH HOTP support for recovery codes
- [ ] WebAuthn/Passkeys support

## License

Authly is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPLv3) license. Contact us for commercial licensing options.
