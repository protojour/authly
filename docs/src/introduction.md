# Introduction

Authly is a flexible Attribute-based Access Control (ABAC) Identity and Access Management (IAM) solution with minimalist Service Mesh control plane and data plane capabilitites.

The Authly server can be run standalone for its IAM features, but relies on mTLS for service client authentication, and can provision such services with client certificates from a mesh-local Certificate Authority (CA), either manually, through a native Rust client ([`authly-client`](https://crates.io/crates/authly-client)) through its language bindings (TBA), or the minimalist sidecar proxy [proxly](https://github.com/protojour/proxly).
