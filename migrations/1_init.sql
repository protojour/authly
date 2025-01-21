-- The version of the master encryption key Authly is currently using
CREATE TABLE cr_master_version (
    version BLOB NOT NULL,
    created_at DATETIME NOT NULL
);

-- Envelope encryption for Property Data Encryption Keys
CREATE TABLE cr_prop_dek (
    prop_id BLOB NOT NULL PRIMARY KEY,
    nonce BLOB NOT NULL,
    ciph BLOB NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE tlskey (
    purpose TEXT NOT NULL PRIMARY KEY,
    expires_at DATETIME NOT NULL,
    cert BLOB NOT NULL,
    key_nonce BLOB NOT NULL,
    key_ciph BLOB NOT NULL
);

CREATE TABLE authority (
    aid BLOB NOT NULL PRIMARY KEY,
    kind TEXT NOT NULL,
    url TEXT,
    hash BLOB
);

CREATE TABLE local_setting (
    aid BLOB NOT NULL,
    setting INTEGER NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE session (
    token BLOB NOT NULL PRIMARY KEY,
    eid BLOB NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE ent_attr (
    aid BLOB NOT NULL,
    eid BLOB NOT NULL,
    attrid BLOB NOT NULL,

    PRIMARY KEY (eid, attrid)
);

CREATE TABLE ent_text_attr (
    aid BLOB NOT NULL,
    eid BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    value TEXT NOT NULL,

    PRIMARY KEY (eid, prop_id)
);

CREATE TABLE ent_ident (
    aid BLOB NOT NULL,
    eid BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    fingerprint BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciph BLOB NOT NULL,

    PRIMARY KEY (eid, prop_id),
    UNIQUE (prop_id, fingerprint)
);

CREATE TABLE ent_rel (
    aid BLOB NOT NULL,
    rel_id BLOB NOT NULL,
    subject_eid BLOB NOT NULL,
    object_eid BLOB NOT NULL,

    PRIMARY KEY (rel_id, subject_eid, object_eid)
);

CREATE TABLE svc_ent_prop (
    aid BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    svc_eid BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (svc_eid, label)
);

CREATE TABLE svc_ent_attrlabel (
    aid BLOB NOT NULL,
    id BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (prop_id, label)
);

CREATE TABLE svc_res_prop (
    aid BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    svc_eid BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (svc_eid, label)
);

CREATE TABLE svc_res_attrlabel (
    aid BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    prop_id BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (prop_id, label)
);

CREATE TABLE svc_policy (
    aid BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    svc_eid BLOB NOT NULL,
    label TEXT NOT NULL,
    policy_pc BLOB NOT NULL,

    UNIQUE (svc_eid, label)
);

CREATE TABLE svc_policy_binding (
    aid BLOB NOT NULL,
    svc_eid BLOB NOT NULL,
    attr_matcher_pc BLOB NOT NULL,
    policy_ids_pc BLOB NOT NULL
);
