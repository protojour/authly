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

CREATE TABLE authly_instance (
    key TEXT NOT NULL PRIMARY KEY,
    eid BLOB NOT NULL,
    private_key_nonce BLOB NOT NULL,
    private_key_ciph BLOB NOT NULL
);

CREATE TABLE tls_cert (
    -- CA or identity
    kind TEXT NOT NULL,
    certifies_eid BLOB NOT NULL,
    signed_by_eid BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    der BLOB NOT NULL
);

-- Any kind of directory, including other Authly Authorities
CREATE TABLE directory (
    dir_id BLOB NOT NULL PRIMARY KEY,
    kind TEXT NOT NULL,
    url TEXT,
    hash BLOB
    -- created_at DATETIME NOT NULL,
    -- created_by_eid BLOB NOT NULL,
    -- updated_at DATETIME NOT NULL
);

CREATE TABLE local_setting (
    dir_id BLOB NOT NULL,
    setting INTEGER NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE session (
    token BLOB NOT NULL PRIMARY KEY,
    eid BLOB NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE ent_attr (
    dir_id BLOB NOT NULL,
    eid BLOB NOT NULL,
    attrid BLOB NOT NULL,

    PRIMARY KEY (eid, attrid)
);

CREATE TABLE ent_ident (
    dir_id BLOB NOT NULL,
    eid BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    fingerprint BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciph BLOB NOT NULL,

    PRIMARY KEY (eid, prop_id),
    UNIQUE (prop_id, fingerprint)
);

CREATE TABLE ent_rel (
    dir_id BLOB NOT NULL,
    rel_id BLOB NOT NULL,
    subject_eid BLOB NOT NULL,
    object_eid BLOB NOT NULL,

    PRIMARY KEY (rel_id, subject_eid, object_eid)
);

-- Text attributes for any database object
-- TODO: Labels can move into a separate table since they require directory-oriented indexing?
CREATE TABLE obj_text_attr (
    dir_id BLOB NOT NULL,
    obj_id BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    value TEXT NOT NULL,

    PRIMARY KEY (obj_id, prop_id)
);

-- Namespace: entity property
CREATE TABLE ns_ent_prop (
    dir_id BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    ns_id BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (ns_id, label)
);

-- Namespace: entity property attribute label
CREATE TABLE ns_ent_attrlabel (
    dir_id BLOB NOT NULL,
    id BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (prop_id, label)
);

-- Namespace: resource property
CREATE TABLE ns_res_prop (
    dir_id BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    ns_id BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (ns_id, label)
);

-- Namespace: resource attribute label
CREATE TABLE ns_res_attrlabel (
    dir_id BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    prop_id BLOB NOT NULL,
    label TEXT NOT NULL,

    UNIQUE (prop_id, label)
);

-- Service: namespace participation
CREATE TABLE svc_namespace (
    dir_id BLOB NOT NULL,
    svc_eid BLOB NOT NULL,
    ns_id BLOB NOT NULL,

    PRIMARY KEY (svc_eid, ns_id)
);

-- TODO: Should policies be associated to namespaces?
CREATE TABLE policy (
    dir_id BLOB NOT NULL,
    id BLOB NOT NULL PRIMARY KEY,
    label TEXT NOT NULL,
    policy_pc BLOB NOT NULL,

    UNIQUE (label)
);

-- Policy binding - attribute matchers
CREATE TABLE polbind_attr_match (
    dir_id BLOB NOT NULL,
    polbind_id BLOB NOT NULL,
    attr_id BLOB NOT NULL,

    PRIMARY KEY (polbind_id, attr_id)
);

-- Policy binding - policy implication
CREATE TABLE polbind_policy (
    dir_id BLOB NOT NULL,
    polbind_id BLOB NOT NULL,
    policy_id BLOB NOT NULL,

    PRIMARY KEY (polbind_id, policy_id)
);

-- This table has one entry if Authly is trying to become a mandate of an authority
CREATE TABLE ma_authority_submission (
    created_at DATETIME NOT NULL,
    created_by_eid BLOB NOT NULL,
    url TEXT NOT NULL,
    code BLOB NOT NULL
);

-- This table has one entry if Authly is trying to become a mandate of an authority
CREATE TABLE ma_authority (
    created_at DATETIME NOT NULL,
    created_by_eid BLOB NOT NULL,
    url TEXT NOT NULL,
    eid BLOB NOT NULL
);

-- Generated codes for mandate registration to this authority
CREATE TABLE am_mandate_submission_code (
    code_fingerprint BLOB NOT NULL PRIMARY KEY,
    created_at DATETIME NOT NULL,
    created_by_eid BLOB NOT NULL
);

CREATE TABLE am_mandate (
    mandate_eid BLOB NOT NULL PRIMARY KEY,
    granted_by_eid BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    mandate_type TEXT NOT NULL,
    last_connection_time DATETIME NOT NULL,

    UNIQUE (public_key)
);