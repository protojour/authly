-- Any kind of directory, including other Authly Authorities
CREATE TABLE directory (
    key integer NOT NULL PRIMARY KEY,
    parent_key BLOB REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    id BLOB NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    url TEXT,
    hash BLOB,
    label TEXT UNIQUE
);

CREATE TABLE namespace (
    key INTEGER NOT NULL PRIMARY KEY,
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    id BLOB NOT NULL UNIQUE,
    upd DATETIME NOT NULL,
    label TEXT NOT NULL
);

CREATE TABLE prop (
    key INTEGER PRIMARY KEY,
    dir_key INTEGER NOT NULL REFERENCES directory(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    ns_key INTEGER NOT NULL REFERENCES namespace(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    id BLOB NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    upd DATETIME NOT NULL,
    label TEXT
);

CREATE TABLE attr (
    key INTEGER PRIMARY KEY,
    dir_key INTEGER NOT NULL REFERENCES directory(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    prop_key INTEGER NOT NULL REFERENCES prop(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    id BLOB NOT NULL UNIQUE,
    upd DATETIME NOT NULL,
    label TEXT
);

-- The version of the master encryption key Authly is currently using
CREATE TABLE cr_master_version (
    version BLOB NOT NULL,
    created_at DATETIME NOT NULL
);

-- Envelope encryption for Property Data Encryption Keys
CREATE TABLE cr_prop_dek (
    prop_key INTEGER NOT NULL PRIMARY KEY REFERENCES prop(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
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

CREATE TABLE session (
    token BLOB NOT NULL PRIMARY KEY,
    eid BLOB NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE directory_audit (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    upd DATETIME NOT NULL,
    updated_by_eid BLOB NOT NULL
);

CREATE TABLE local_setting (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    setting INTEGER NOT NULL,
    value TEXT NOT NULL,
    upd DATETIME NOT NULL
);

CREATE TABLE ent_attr (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    eid BLOB NOT NULL,
    attr_key INTEGER NOT NULL REFERENCES attr(key) DEFERRABLE INITIALLY DEFERRED,
    upd DATETIME NOT NULL,

    PRIMARY KEY (eid, attr_key)
);

CREATE TABLE ent_rel (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    prop_key INTEGER NOT NULL REFERENCES prop(key) DEFERRABLE INITIALLY DEFERRED,
    subject_eid BLOB NOT NULL,
    object_eid BLOB NOT NULL,
    upd DATETIME NOT NULL,

    PRIMARY KEY (prop_key, subject_eid, object_eid)
);

CREATE TABLE obj_ident (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    obj_id BLOB NOT NULL,
    prop_key INTEGER NOT NULL REFERENCES prop(key) DEFERRABLE INITIALLY DEFERRED,
    fingerprint BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciph BLOB NOT NULL,
    upd DATETIME NOT NULL,

    PRIMARY KEY (obj_id, prop_key),
    UNIQUE (prop_key, fingerprint)
);

-- Text attributes for any database object
CREATE TABLE obj_text_attr (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    obj_id BLOB NOT NULL,
    prop_key INTEGER NOT NULL REFERENCES prop(key) DEFERRABLE INITIALLY DEFERRED,
    upd DATETIME NOT NULL,
    value TEXT NOT NULL,

    PRIMARY KEY (obj_id, prop_key)
);

CREATE TABLE obj_foreign_dir_link (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    foreign_id BLOB NOT NULL,
    obj_id BLOB NOT NULL,
    upd DATETIME NOT NULL,
    overwritten INTEGER NOT NULL,

    PRIMARY KEY (dir_key, foreign_id)
);

-- Service entities
CREATE TABLE svc (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    svc_eid BLOB NOT NULL PRIMARY KEY,
    upd DATETIME NOT NULL,
    hosts_json TEXT
);

-- Service: namespace participation
CREATE TABLE svc_namespace (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    svc_eid BLOB NOT NULL REFERENCES svc(svc_eid) DEFERRABLE INITIALLY DEFERRED,
    ns_key INTEGER NOT NULL REFERENCES namespace(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    upd DATETIME NOT NULL,

    PRIMARY KEY (svc_eid, ns_key)
);

-- TODO: Should policies be associated to namespaces?
CREATE TABLE policy (
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    id BLOB NOT NULL PRIMARY KEY,
    upd DATETIME NOT NULL,
    label TEXT NOT NULL,
    policy_pc BLOB NOT NULL,

    UNIQUE (label)
);

-- Policy binding
CREATE TABLE polbind (
    key INTEGER PRIMARY KEY,
    dir_key INTEGER NOT NULL REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    upd DATETIME NOT NULL
);

-- Policy binding - attribute matchers
CREATE TABLE polbind_attr_match (
    polbind_key INTEGER NOT NULL REFERENCES polbind(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    attr_key INTEGER NOT NULL REFERENCES attr(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,

    PRIMARY KEY (polbind_key, attr_key)
);

-- Policy binding - policy implication
CREATE TABLE polbind_policy (
    polbind_key INTEGER NOT NULL REFERENCES polbind(key) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    policy_id BLOB NOT NULL REFERENCES policy(id) DEFERRABLE INITIALLY DEFERRED,

    PRIMARY KEY (polbind_key, policy_id)
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

CREATE TABLE dir_oauth (
    dir_key INTEGER PRIMARY KEY REFERENCES directory(key) DEFERRABLE INITIALLY DEFERRED,
    upd DATETIME NOT NULL,
    client_id TEXT NOT NULL,

    auth_url TEXT NOT NULL,
    auth_req_scope TEXT,
    auth_req_client_id_field TEXT,
    auth_req_nonce_field TEXT,
    auth_res_code_path TEXT,

    token_url TEXT NOT NULL,
    token_req_client_id_field TEXT,
    token_req_client_secret_field TEXT,
    token_req_code_field TEXT,
    token_req_callback_url_field TEXT,
    token_res_access_token_field TEXT,

    user_url TEXT NOT NULL,
    user_res_id_path TEXT,
    user_res_email_path TEXT
);
