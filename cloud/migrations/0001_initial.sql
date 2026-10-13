PRAGMA foreign_keys = ON;
CREATE TABLE users(id TEXT PRIMARY KEY, login TEXT NOT NULL, created_at INTEGER NOT NULL, sync_enabled INTEGER NOT NULL DEFAULT 0 CHECK(sync_enabled IN(0,1)));
CREATE TABLE sessions(hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires_at INTEGER NOT NULL, authenticated_at INTEGER NOT NULL);
CREATE TABLE oauth_states(hash TEXT PRIMARY KEY, verifier TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE pairing(hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE devices(id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER, last_seen_at INTEGER);
CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,timestamp INTEGER NOT NULL, operation TEXT NOT NULL,decision TEXT NOT NULL,executed INTEGER NOT NULL,reason_code TEXT NOT NULL, received_at INTEGER NOT NULL,UNIQUE(device_id,event_id));
CREATE INDEX events_user_seq ON events(user_id,seq DESC);
CREATE INDEX events_retention ON events(received_at);
CREATE TABLE rates(bucket TEXT PRIMARY KEY, count INTEGER NOT NULL,expires_at INTEGER NOT NULL);

CREATE INDEX devices_user ON devices(user_id);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX pairing_user ON pairing(user_id);
CREATE INDEX events_user_received ON events(user_id,received_at);
