# Authly configuration documents

Authly's attribute-based identity and access control model is configured through sequentially applied, declarative TOML documents. Any number of these documents can be included from the configuration setting [`AUTHLY_DOCUMENT_PATH`](configuration.md), and any definition can depend on a previous defintion. To give them some sort of order, they are usually prefixed with a number to ensure they are processed correctly in lexicographical order, e.g.:

```
0_core.toml
1_services.toml
2_users.toml
```

Although the documents are intended to be human-readable and -writable, the definitions therein will eventually be accessible through a more user-friendly admin UI.


## A full example, step by step

```toml
{{#include examples/full_example/0_all.toml:1:2}}
```

The document requires an [`authly-document`](#authly-document) clause at the top, with a UUID `id` value.

```toml
{{#include examples/full_example/0_all.toml:4:8}}
```

This defines the [`"arx"` gateway](https://github.com/protojour/arx) as a kubernetes [service-entity](#service-entity). The gateway is responsible for opening up the public aspects of Authly to the world outside the cluster.

Service entity ids are prefixed by `s.`.

The built-in _attribute triplets_ `"authly:role:authenticate"` and `"authly:role:get_access_token"` allows anyone to authenticate and get access tokens through the gateway. An attribute triplet is a colon-separated `namespace:label:attribute` string.

The `kubernetes-account` is used by Authly to provision the service with an mTLS client certificate, used for (service) authentication.
It only specifies an account name, and not a `namespace`. Not specifying the namespace means the same namespace that Authly itself runs within.

```toml
{{#include examples/full_example/0_all.toml:10:14}}
```

This defines the `"ultradb"` [service-entity](#service-entity), hosted as a kubernetes service behind the `"arx"`. Service-enitity labels are exposed as _namespaces_ in the Authly model.

```toml
{{#include examples/full_example/0_all.toml:16:19}}
```

This defines the `"ultradb_gui"` (_client_) [service-entity](#service-entity), hosted by `"ultradb"`.

```toml
{{#include examples/full_example/0_all.toml:21:24}}
```

This defines the [entity-property](#entity-property) `"role"` for the `"ultradb_gui"` client.

Its attributes are `"user"` and `"admin"`.

In other words, we make the client responsible for the concept of a (persona) entity role, since users access the service through the client.

```toml
{{#include examples/full_example/0_all.toml:26:29}}
```

This defines the [resource-property](#resource-property) `"action"` for the `"ultradb"` service.

Its attributes are `"read"` and `"write"`.

In other words, we make the service is responsible for its own resources, since users access resources (data) via the service's API.

```toml
{{#include examples/full_example/0_all.toml:31:33}}
```

This defines a [policy](#policy) called `"allow for GUI user"`.

The policy must either define an `allow` or a `deny` expression. This policy will resolve to `allow` if the expression resolves to `true`.

`Subject` is the one being access-controlled. `ultradb_gui:role` is a namespaced entity property, and `ultradb_gui:role:user` is an attribute assigned to an entity (see below).

Referencing the entity-properties above, this should read as *"allow if the Subject has the ultradb_gui role user".*

```toml
{{#include examples/full_example/0_all.toml:35:37}}
```

This defines a [policy](#policy) called `"allow for GUI admin"`, similar to the one above.

Referencing the entity-properties above, this should read as *"allow if the Subject has the ultradb_gui role admin".*

```toml
{{#include examples/full_example/0_all.toml:39:41}}
```

This defines a [policy-binding](#policy-binding), from a list of policies to a list of colon-separated attribute triplets (`namespace:label:attribute`).

Referencing the resource-properties and policies, this should read as *"GUI users and GUI admins are allowed the ultradb action read"*.

```toml
{{#include examples/full_example/0_all.toml:43:45}}
```

This defines a [policy-binding](#policy-binding), from a list of policies to a list of colon-separated attribute triplets (`namespace:label:attribute`).

Referencing the resource-properties and policies, this should read as *"GUI admins are allowed the ultradb action write"*.

```toml
{{#include examples/full_example/0_all.toml:47:49}}
```

This defines a (persona) [entity](#entity), `"Mr. User"`. For now, they don't have any access credentials.

Persona entity ids are prefixed by `p.`.

```toml
{{#include examples/full_example/0_all.toml:51:53}}
```

This defines a (persona) [entity](#entity), `"Ms. Admin"`. For now, they don't have any access credentials.

```toml
{{#include examples/full_example/0_all.toml:55:57}}
```

This defines an [entity-attribute-assignment](#entity-attribute-assignment).

Referencing the entities and entity-properties above, this should read as *"Mr. User has the ultradb_gui role user"*.

```toml
{{#include examples/full_example/0_all.toml:59:61}}
```

This defines an [entity-attribute-assignment](#entity-attribute-assignment).

Referencing the entities and entity-properties above, this should read as *"Ms. Admin has the ultradb_gui role admin"*.

To summarize, this document defines three [service-entities](#service-entity), and allows anyone to authenticate and resolve an authentication token through the service "arx" (if they had credentials). We define some [entity-properties](#entity-property) and [resource-properties](#resource-property) to describe our access control model, and [policies](#policy) are bound to the resource-properties through [policy-bindings](#policy-binding). Finally, a pair of [entities](#entity) are defined, and are assigned entity attributes through [entity-attribute-assignments](#entity-attribute-assignment).


## Clauses

### `[authly-document]`

*Required*. Metadata about the document. Every document must have one of these clauses the top.

**Properties:**

- `id`: *Required*. A UUID value.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:1:2}}
```

### `[[entity]]`

An entity definition, e.g. a persona or a group.

**Properties:**

- `eid`: *Required*. The entity id. Persona entity ids are prefixed by `p.`, while group entity ids are prefixed by `g.`. The value is a hex-encoded 128-bit value.
- `label`: A label for the entity visible in the document namespace.
- `attributes`: Attributes bound to the entity. See [entity-attribute-assignment](#entity-attribute-assignment).
- `username`: A list of usernames.
- `email`: A list of email addresses.
- `password-hash`: A list of password hashes.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:4:10}}
```

### `[[service-entity]]`

A service entity definition.

Services are authenticated through client certificates rather than traditional credentials.

**Properties:**

- `eid`: *Required*. The entity id. Service entity ids are prefixed by `s.`.
- `label`: A label for the entity visible in the document namespace.
- `attributes`: Attributes bound to the entity. See [entity-attribute-assignment](#entity-attribute-assignment).
- `metadata`: Metadata about this entity. The metadata is not used by authly itself, but can be used by services which have read access to the entity.
- `hosts`: List of service hostnames.
- `kubernetes-account`: An optional Kubernetes account definition.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:12:16}}
```

### `[[email]]`

An email address assignment.

Can also be given as part of an `email` property list of an [`[[entity]]`](#entity) clause.

**Properties:**

- `entity`: The label of the entity that is assigned this address.
- `value`: The address itself.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:18:20}}
```

### `[[password-hash]]`

A password hash assignment.

Can also be given as part of a `password-hash` property list of an [`[[entity]]`](#entity) clause.

**Properties:**

- `entity`: The label of the entity that is assigned this password.
- `hash`: The password hash itself.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:26:28}}
```

### `[[members]]`

A members assignment, giving a (group) entity other entities as members.

In the Authly model, any kind of entity may have members.

**Properties:**

- `entity`: The label of the entity that members are assigned to.
- `members`: List of entity labels of the members.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:34:36}}
```

### `[[domain]]`

A domain declaration.

**Properties:**

- `label`: *Required*. A label for an entity visible in the document namespace.
- `metadata`: Metadata about this domain. The metadata is not used by Authly itself, but can be read and used by services.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:38:40}}
```

### `[[service-domain]]`

An association of a service and a domain the service can use.

**Properties:**

- `service`: *Required*. A label identifying the implied service-entity.
- `domain`: *Required*. A label identifying the domain that will be exposed to the service.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:42:44}}
```

### `[[entity-property]]`

A definition of an entity property.

**Properties:**

- `namespace`: *Required*. The label of the namespace this property is defined inside.
- `label`: *Required*. The property label.
- `attributes`: The list of attributes of the property.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:46:49}}
```

### `[[entity-attribute-assignment]]`

An entity attribute binding, which assigns attributes to entities.

Can also be given as part of a `attributes` property list on an [`[[entity]]`](#entity) or [`[[service-entity]]`](#service-entity).

**Properties:**

- `entity`: *Required*. An Entity ID or label identifying the entity to assign to.
- `attributes`: *Required*. The attributes assigned to the entity.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:51:53}}
```

### `[[resource-property]]`

A definition of a resource property.

**Properties:**

- `namespace`: *Required*. The label of the namespace this property is defined inside.
- `label`: *Required*. The property label.
- `attributes`: The list of attributes of the property.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:55:58}}
```

### `[[policy]]`

A policy definition.

A policy must contain either an `allow` or `deny` expression.
Access _may_ be granted if any allow-policy evaluates to `true`, unless there are _applicable deny-policies_.
deny-policies are stronger than allow-policies: Access will be denied if _any_ applicable deny-policy evaluates to `true`.

**Properties:**

- `service`: *Required*. A label identifying the implied service-entity.
- `domain`: *Required*. A label identifying the domain that will be exposed to the service.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:60:62}}
```

### `[[policy-binding]]`

A policy binding.

A policy binding makes policies _applicable_ in the context of the binding's attribute matcher.

**Properties:**

- `attributes`: *Required*. A set of attribute triples that must be matched for the selected policies to apply.
- `policies`: *Required*. A set of applied policies, by label.

**Example:**

```toml
{{#include examples/clause_examples/0_all.toml:64:66}}
```
