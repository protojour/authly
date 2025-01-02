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

Service authentication requires a client certificate signed by Authly.
Authly as a Trusted Platform Module therefore has to integrate with the operating system to distribute certificates through other means than network calls.

#### Example: kubernetes mode
Authly is the authority on service identities, therefore Authly also has to be a controller for k8s service accounts.
When authly sees a new service that could be deployed in the cluster, authly will issue a corresponding service account.

Authly can issue service client certificates in two possible ways.

##### Certificate and key distribution using secrets
Authly can generate the client certificate and private keys itself, then distributes them as kubernetes secrets.
This method has the downside that the resulting secret(s) needs to be named and requested by a deployment by secret name, thereby potentially exposing the secret.

##### Certificate signing request API using kubernetes service account token
Authly can provide a kubernetes-specific extension REST API accepting a k8s service account JWT token.
This API call issues a client certificate that proves the service is who it is based on which kubernetes service account it runs.
The JWT token is automatically mounted by kubernetes at `/var/run/secrets/kubernetes.io/serviceaccount/token`, and is a system-managed secret and is harder to tamper with.
Authly will verify the token signature.

Authly keeps a mapping between kubernetes service account name (which it manages) and entity ID.
The common name of the signed certificate is the service entity ID.

Flow:
1. Client calls `https://authly.local/api/k8s/csr` using `Authorization: Bearer $K8S_SERVICE_ACCOUNT_TOKEN`
2. Client obtains the client certificate the proves it is the indicated entity
3. Further calls to Authly uses the client certificate for authentication

Pros: This way the client private key never leaves the client service (compared to authly distributing the secrets).
Cons: Requires crypto for generating a key pair in every authly client

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

