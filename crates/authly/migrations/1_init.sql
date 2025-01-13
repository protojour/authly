CREATE TABLE tlskey (
    purpose TEXT NOT NULL PRIMARY KEY,
    expires_at DATETIME NOT NULL,
    cert BLOB NOT NULL,
    private_key BLOB NOT NULL
);

CREATE TABLE authority (
    aid BLOB NOT NULL PRIMARY KEY,
    kind TEXT NOT NULL,
    url TEXT,
    hash BLOB
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

CREATE TABLE ent_rel (
    aid BLOB NOT NULL,
    subj_eid BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    obj_eid BLOB NOT NULL,

    PRIMARY KEY (subj_eid, prop_id, obj_eid)
);

CREATE TABLE ent_ident (
    aid BLOB NOT NULL,
    eid BLOB NOT NULL,
    kind TEXT NOT NULL,
    ident TEXT NOT NULL,

    UNIQUE (kind, ident)
);

CREATE TABLE ent_password (
    aid BLOB NOT NULL,
    eid BLOB NOT NULL PRIMARY KEY,
    hash TEXT NOT NULL
);

CREATE TABLE svc (
    aid BLOB NOT NULL,
    eid BLOB NOT NULL PRIMARY KEY,
    label TEXT NOT NULL
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
    expr_pc BLOB NOT NULL,

    UNIQUE (svc_eid, label)
);

CREATE TABLE svc_ext_k8s_service_account (
    aid BLOB NOT NULL,
    svc_eid BLOB NOT NULL,
    namespace TEXT NOT NULL,
    account_name TEXT NOT NULL,

    UNIQUE (namespace, account_name)
);
