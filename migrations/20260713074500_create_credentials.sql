CREATE TABLE credential_metadata (
    credential_id BLOB PRIMARY KEY NOT NULL,
    rp_id TEXT NOT NULL,
    user_handle BLOB NOT NULL,
    user_name TEXT,
    user_display_name TEXT,
    sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE credential_keyslots (
    keyslot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id BLOB NOT NULL REFERENCES credential_metadata(credential_id) ON DELETE CASCADE,
    slot_kind TEXT NOT NULL CHECK (slot_kind IN ('primary', 'recovery')),
    slot_label TEXT,
    policy_selection TEXT,
    policy_digest BLOB,
    tpm_private BLOB NOT NULL,
    tpm_public BLOB NOT NULL,
    public_key_x BLOB NOT NULL,
    public_key_y BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (credential_id, slot_kind)
);

CREATE TABLE credential_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyslot_id INTEGER NOT NULL REFERENCES credential_keyslots(keyslot_id) ON DELETE CASCADE,
    token_type TEXT NOT NULL CHECK (token_type IN ('passphrase')),
    label TEXT,
    passphrase_salt BLOB NOT NULL,
    passphrase_hash BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (keyslot_id, token_type)
);

CREATE INDEX credential_metadata_rp_id_idx ON credential_metadata(rp_id);
CREATE INDEX credential_keyslots_credential_id_idx ON credential_keyslots(credential_id);
CREATE INDEX credential_tokens_keyslot_id_idx ON credential_tokens(keyslot_id);
