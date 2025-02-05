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
docker run ghcr.io/protojour/authly:pre-alpha
```

It uses an embedded database and _can_ run independently, _in principle_. However, it is not intended to run directly exposed to the internet, and should have access to a secrets store. Refer to [Quickstart](#quickstart) for more complete examples.

## Quickstart

Examples should be run using our `justfile` tasks. Refer to the [just](https://just.systems/man/en/introduction.html) documentation for how to install it.

### Kubernetes example (recommended)

An example Kubernetes deployment is available in [`testfiles/k8s`](testfiles/k8s), which includes the Authly-compatible [Arx gateway](https://github.com/protojour/arx), [OpenBao](https://openbao.org/) for its main encryption key, the correct routing and setup for Authly to provision [an example service](crates/authly-testservice) with mTLS, and uses Kubernetes Secrets for its core identity.

```bash
just k8s-test-deploy
```

### Docker example

A minimal `docker compose` development example is available in [`testfiles/docker/docker-compose.yml`](testfiles/docker/docker-compose.yml).

```bash
just docker-test-deploy
```

## Security features

The Authly server relies on mTLS for service client authentication, and can provision such services with client certificates from a (mesh-local or global) Certificate Authority, either manually (CLI commands), through a native [Rust client](https://crates.io/crates/authly-client), through its language bindings (TBA), or a minimalist sidecar proxy (TBA).

It uses an embedded [`hiqlite`](https://github.com/sebadob/hiqlite) database with envelope encrypted user data for encryption-at-rest. The master encryption key should be stored in a secure way.

Authly is not yet audited. We invite anyone to examine or critique its security model, and report any vulnerabilities.

## Feature roadmap

Authly is pre-alpha software, currently with a minimal feature set, but several high-level features are planned:

- [x] Attribute-based data model
- [x] Policy DSL
- [x] High-availability cluster mode
- [x] Database encryption-at-rest
- [x] mTLS provisioning for services
- [x] Kubernetes example setup
- [x] Docker example setup
- [x] Minimal login UI
- [ ] Federation and authority/mandate relations
- [ ] OAuth 2.0 + OpenID Connect support
- [ ] `authly-client` language bindings
- [ ] `authly-client` standalone sidecar proxy
- [ ] Detailed documentation
- [ ] User registration and recovery
- [ ] SMTP email support
- [ ] OATH TOTP support for authenticator apps
- [ ] OATH HOTP support for recovery codes

## License

Authly is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPLv3) license. Contact us for commercial licensing options.
