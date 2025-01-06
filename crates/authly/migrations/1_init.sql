CREATE TABLE tlskey (
    purpose TEXT NOT NULL PRIMARY KEY,
    expires_at DATETIME NOT NULL,
    cert BLOB NOT NULL,
    private_key BLOB NOT NULL
);

CREATE TABLE authority (
    eid BLOB NOT NULL PRIMARY KEY,
    kind TEXT NOT NULL
);

CREATE TABLE session (
    token BLOB NOT NULL PRIMARY KEY,
    eid BLOB NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE entity_credential (
    authority_eid BLOB NOT NULL,
    eid BLOB NOT NULL PRIMARY KEY,
    ident TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL
);

CREATE TABLE entity_tag (
    eid BLOB NOT NULL,
    tag BLOB NOT NULL,

    PRIMARY KEY (eid, tag)
);

CREATE TABLE entity_rel (
    authority_eid BLOB NOT NULL,
    subj_eid BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    obj_eid BLOB NOT NULL,

    PRIMARY KEY (subj_eid, prop_id, obj_eid)
);

CREATE TABLE svc (
    authority_eid BLOB NOT NULL,
    eid BLOB NOT NULL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE svc_eprop (
    authority_eid BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    svc_eid BLOB NOT NULL,
    name TEXT NOT NULL,

    UNIQUE (svc_eid, name)
);

CREATE TABLE svc_etag (
    id BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    name TEXT NOT NULL,

    UNIQUE (prop_id, name)
);

CREATE TABLE svc_rprop (
    authority_eid BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    svc_eid BLOB NOT NULL,
    name TEXT NOT NULL,

    UNIQUE (svc_eid, name)
);

CREATE TABLE svc_rtag (
    id BLOB NOT NULL PRIMARY KEY,
    prop_id BLOB NOT NULL,
    name TEXT NOT NULL,

    UNIQUE (prop_id, name)
);

CREATE TABLE svc_ext_k8s_service_account (
    authority_eid BLOB NOT NULL,
    svc_eid BLOB NOT NULL,
    namespace TEXT NOT NULL,
    account_name TEXT NOT NULL,

    UNIQUE (namespace, account_name)
);
