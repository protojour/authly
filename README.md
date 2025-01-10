# Authly/next

Experimental prototype that tries some new things.

* Uses an embedded database (and a raft cluster) instead of an external client/server database
* Federation (planned)
* Disallow string literals in policy rule engine (must predefine every value), for client-side policy-decision-point

## Design outline/proposals
### Authentication
Communication with authly is authenticated in two layers, reflecting the service/user duality.

* User authentication is implemented using tokens
* Service authentication is implemented using mutual TLS (mTLS)

Service authentication requires a client certificate signed by Authly (mTLS).
All traffic to Authly originates from some service, it is not possible to use Authly's API without being an authenticated service.
This is true regardless of whether the API used is a "service API" or "user API".
The APIs are always called through some proxy, e.g. a gateway application, Authly is never directly exposed on the internet.
This way, all interaction with the Authly web API will ALWAYS happen using an implicit context of "which service made the call".

#### Example: kubernetes mode
Authly is the authority on service identities, therefore Authly also has to be a controller for k8s service accounts.
When authly sees a new service that could be deployed in the cluster, authly will issue a corresponding service account.

Authly can issue service client certificates in two possible ways:

##### 1. Certificate and key distribution using secrets
Authly can generate the client certificate and private keys itself, then distribute them as kubernetes secrets.
This method has the downside that the resulting secret(s) need to be named and requested by a deployment by secret name, thereby potentially exposing the secret,
because secrets can be freely mounted by an actor that is allowed to define deployments.

##### 2. Certificate signing request API using kubernetes service account token
Authly can provide a kubernetes-specific extension REST API accepting a k8s service account JWT token.
This API call issues a client certificate that proves the service is who it is based on which kubernetes service account it runs.
The JWT token is automatically mounted by kubernetes at `/var/run/secrets/kubernetes.io/serviceaccount/token`, and is a system-managed secret and is harder to tamper with.
Authly will verify the token signature.

Authly keeps a mapping between kubernetes service account name (which it manages) and entity ID.
The common name (CN) of the signed client certificate is the service entity ID.

Flow:
1. Client (service) starts up and generates a key pair
2. Client calls `https://k8s.authly.local/api/csr` using `Authorization: Bearer $K8S_SERVICE_ACCOUNT_TOKEN` to sign the public key
3. Client obtains the client certificate that proves it is the indicated entity
4. Further calls to Authly uses the client certificate for authentication

Pros: This way the client private key never leaves the client service (compared to authly distributing the secrets).
Cons: Requires crypto for generating a key pair in every authly client.

note: `k8s.authly.local` must be a separate network service, that listens on a separate socket address, with TLS client auth turned off, because of the technical limitation that client auth/mTLS can't conditionally depend on a HTTP path (the full TLS handshake must finish before any HTTP path dispatch happens).

### Authly documents
Authly needs a way for solution owners to easily inject definition manifests that get distributed and fulfilled by authly instances.
The primary way of mutating Authly state is to manipulate and re-apply documents.

Documents are written the `TOML` format.

Example documents can be found in the `example/` directory.

## Major design tasks
Some things are seriously underspecified:

### Multi-client access control and how that relates to service contracts
Request pipeline may flow through different services, each service having a unique contract with the subject and should share nothing.
There has to be some token (contract-token) that represents a session and a service contract and that token must stay private to that (distributed) service,
so some sort of cryptography likely needs to be used.

## TODO
* GC expired sessions

## Questions
It seems weird that `mfaNeeded` a global setting. Intuitively it should be the intent/context of a specific authenticaion that mandates MFA.
E.g. certain "dangerous" operations may require MFA or higher degree of security, but trivial operations would not need to.

