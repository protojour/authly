CREATE TABLE session (
    token BLOB NOT NULL PRIMARY KEY,
    eid BLOB NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE entity_credential (
    eid BLOB NOT NULL PRIMARY KEY,
    ident TEXT NULL UNIQUE,
    secret_hash TEXT NOT NULL
);

CREATE TABLE entity_tag (
    eid BLOB NOT NULL,
    tag BLOB NOT NULL,

    PRIMARY KEY (eid, tag)
);

CREATE TABLE entity_rel (
    subj_eid BLOB NOT NULL,
    prop_id BLOB NOT NULL,
    obj_eid BLOB NOT NULL,

    PRIMARY KEY (subj_eid, prop_id, obj_eid)
);

CREATE TABLE svc (
    eid BLOB NOT NULL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE svc_eprop (
    id BLOB NOT NULL PRIMARY KEY,
    svc_eid BLOB NOT NULL REFERENCES svc(eid),
    name TEXT NOT NULL,

    UNIQUE (svc_eid, name)
);

CREATE TABLE svc_etag (
    id BLOB NOT NULL,
    prop_id BLOB NOT NULL REFERENCES svc_eprop(id),
    name TEXT NOT NULL,

    UNIQUE (prop_id, name)
);

CREATE TABLE svc_rprop (
    id BLOB NOT NULL PRIMARY KEY,
    svc_eid BLOB NOT NULL REFERENCES svc(eid),
    name TEXT NOT NULL,

    UNIQUE (svc_eid, name)
);

CREATE TABLE svc_rtag (
    id BLOB NOT NULL PRIMARY KEY,
    prop_id BLOB NOT NULL REFERENCES svc_rprop(id),
    name TEXT NOT NULL,

    UNIQUE (prop_id, name)
);
