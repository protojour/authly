CREATE TABLE session (
    token BLOB NOT NULL PRIMARY KEY,
    eid BLOB NOT NULL,
    expires_at DATETIME NOT NULL
);

CREATE TABLE user_auth (
    eid BLOB NOT NULL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
