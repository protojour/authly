# Authly environment variables

Configuration values are always read from the environment.

These values are closely tied to the platform Authly runs on,
and are not runtime-configurable.

## `AUTHLY_ID`

(**required**; 32-byte hex string; no default)

A unique identifier for this Authly instance. It should be fairly unique, should never change, and is not particularly secret. Global uniqueness is not required, but a form of local uniqueness is required in closed systems running several authly instances. Can be generated with `docker run ghcr.io/protojour/authly generate-authly-id`.

## `AUTHLY_HOSTNAME`

(string; default `authly`)

The hostname against which to generate server certificates.

## `AUTHLY_SERVER_PORT`

(integer; default `443`)

The port on which to run the API/web server.

## `AUTHLY_DOCUMENT_PATH`

(list of path strings; default `/etc/authly/documents`)

A list of paths to scan for documents during startup.

## `AUTHLY_ETC_DIR`

(path string; default `/etc/authly`)

Configuration directory.

## `AUTHLY_DATA_DIR`

(path string; default `/var/lib/authly/data`)

Database directory.

## `AUTHLY_BAO_URL`

(url string; no default)

OpenBao URL for master encryption key storage.

## `AUTHLY_BAO_TOKEN`

(string; no default)

OpenBao token support for legacy setups.

## `AUTHLY_CLUSTER_NODE_ID`

(integer; no default)

## `AUTHLY_CLUSTER_API_NODES`

(ip address string; no default)

## `AUTHLY_CLUSTER_RAFT_NODES`

(ip address string; no default)

## `AUTHLY_CLUSTER_RAFT_SECRET`

(string; no default)

## `AUTHLY_CLUSTER_API_SECRET`

(string; no default)

## `AUTHLY_K8S`

(boolean; default `false`)

## `AUTHLY_K8S_STATEFULSET`

(string; default `authly`)

## `AUTHLY_K8S_HEADLESS_SVC`

(string; default `authly-cluster`)

## `AUTHLY_K8S_REPLICAS`

(integer; default `1`)

## `AUTHLY_K8S_AUTH_HOSTNAME`

(string; no default)

## `AUTHLY_K8S_AUTH_SERVER_PORT`

(integer; no default)

## `AUTHLY_EXPORT_TLS_TO_ETC`

(boolean; default `false`)

Whether to export certificates and identities to `AUTHLY_ETC_DIR`.
