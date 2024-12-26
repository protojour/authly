# Authly/next

Experimental prototype that tries some new things.

* Embedded database instead of external (client/server) and raft cluster
* Federation (planned)
* Disallow string literals in policy rule engine (must predefine every value), for client-side policy-decision-point

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

