use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    str::FromStr,
};

use color_eyre::{
    Result,
    eyre::{WrapErr, eyre},
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::tpm::RecoveryKdf;

type HmacSha256 = Hmac<Sha256>;

pub const DEV_STORE_DIR: &str = ".linux-tpm-fido2-store";
const CREDENTIALS_DATABASE_FILE: &str = "credentials.sqlite";
const HMAC_KEY_FILE: &str = "integrity.hmac-key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCtap2Credential {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub discoverable: bool,
    pub user_id: Option<u32>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub key: StoredTpmKey,
    pub policy: Option<StoredPcrPolicy>,
    pub recovery: Option<StoredRecoverySlot>,
    pub sign_count: u32,
    pub integrity_mac: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPcrPolicy {
    pub selection: String,
    pub digest: Vec<u8>,
    pub policy_ref: Option<Vec<u8>>,
    pub authority_name: Option<Vec<u8>>,
    pub authority_signature: Option<Vec<u8>>,
    pub policy_version: u32,
}

impl StoredPcrPolicy {
    pub fn current_version() -> u32 {
        1
    }

    pub fn is_version_supported(version: u32) -> bool {
        let supported: &[u32] = &[1];
        supported.contains(&version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecoverySlot {
    pub label: Option<String>,
    pub passphrase_salt: Vec<u8>,
    pub passphrase_hash: Vec<u8>,
    pub kdf: RecoveryKdf,
    pub key: StoredTpmKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTpmKey {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
    pub auth_value: Option<Vec<u8>>,
}

fn recovery_kdf_from_database(
    algorithm: &str,
    memory_kib: Option<i64>,
    iterations: Option<i64>,
    parallelism: Option<i64>,
) -> Result<RecoveryKdf> {
    let to_u32 = |name: &str, value: i64| {
        u32::try_from(value).wrap_err_with(|| format!("invalid recovery KDF {name}: {value}"))
    };

    match algorithm {
        "pbkdf2-sha256" => Ok(RecoveryKdf::Pbkdf2Sha256 {
            iterations: to_u32("iterations", iterations.unwrap_or(600_000))?,
        }),
        "argon2id" => Ok(RecoveryKdf::Argon2id {
            memory_kib: to_u32(
                "memory_kib",
                memory_kib.ok_or_else(|| eyre!("Argon2id recovery KDF missing memory_kib"))?,
            )?,
            iterations: to_u32(
                "iterations",
                iterations.ok_or_else(|| eyre!("Argon2id recovery KDF missing iterations"))?,
            )?,
            parallelism: to_u32(
                "parallelism",
                parallelism.ok_or_else(|| eyre!("Argon2id recovery KDF missing parallelism"))?,
            )?,
        }),
        unknown => Err(eyre!("unsupported recovery KDF algorithm: {unknown}")),
    }
}

fn recovery_kdf_database_values(
    kdf: &RecoveryKdf,
) -> (&'static str, Option<i64>, i64, Option<i64>) {
    match kdf {
        RecoveryKdf::Pbkdf2Sha256 { iterations } => {
            ("pbkdf2-sha256", None, i64::from(*iterations), None)
        }
        RecoveryKdf::Argon2id {
            memory_kib,
            iterations,
            parallelism,
        } => (
            "argon2id",
            Some(i64::from(*memory_kib)),
            i64::from(*iterations),
            Some(i64::from(*parallelism)),
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredClientPinState {
    pub pin_salt: Vec<u8>,
    pub pin_verifier: Vec<u8>,
    pub retries: u32,
    pub integrity_mac: Option<Vec<u8>>,
}

pub fn dev_store_dir() -> PathBuf {
    PathBuf::from(DEV_STORE_DIR)
}

pub fn credentials_database_path() -> PathBuf {
    credentials_database_path_in_dir(dev_store_dir())
}

pub fn load_ctap2_credentials() -> Result<Vec<StoredCtap2Credential>> {
    load_ctap2_credentials_from_dir(dev_store_dir(), None)
}

pub fn load_ctap2_credentials_from_dir(
    dir: impl AsRef<Path>,
    user_id: Option<u32>,
) -> Result<Vec<StoredCtap2Credential>> {
    block_on_store(load_ctap2_credentials_async(dir.as_ref(), user_id))
}

pub fn save_ctap2_credentials(credentials: &[StoredCtap2Credential]) -> Result<()> {
    save_ctap2_credentials_to_dir(dev_store_dir(), credentials)
}

pub fn save_ctap2_credentials_to_dir(
    dir: impl AsRef<Path>,
    credentials: &[StoredCtap2Credential],
) -> Result<()> {
    block_on_store(save_ctap2_credentials_async(dir.as_ref(), credentials))
}

pub fn update_ctap2_sign_count_in_dir(
    dir: impl AsRef<Path>,
    credential_id: &[u8],
    sign_count: u32,
) -> Result<()> {
    block_on_store(update_ctap2_sign_count_async(
        dir.as_ref(),
        credential_id,
        sign_count,
    ))
}

pub fn update_ctap2_policy_in_dir(
    dir: impl AsRef<Path>,
    credential_id: &[u8],
    policy: &StoredPcrPolicy,
) -> Result<()> {
    block_on_store(update_ctap2_policy_async(
        dir.as_ref(),
        credential_id,
        policy,
    ))
}

pub fn update_recovery_slot_in_dir(
    dir: impl AsRef<Path>,
    credential_id: &[u8],
    new_private: &[u8],
    new_salt: &[u8],
    new_hash: &[u8],
    kdf: &RecoveryKdf,
) -> Result<()> {
    block_on_store(update_recovery_slot_async(
        dir.as_ref(),
        credential_id,
        new_private,
        new_salt,
        new_hash,
        kdf,
    ))
}

pub fn delete_ctap2_credential_from_dir(dir: impl AsRef<Path>, credential_id: &[u8]) -> Result<()> {
    block_on_store(delete_ctap2_credential_async(dir.as_ref(), credential_id))
}

pub fn load_client_pin_state_from_dir(
    dir: impl AsRef<Path>,
) -> Result<Option<StoredClientPinState>> {
    block_on_store(load_client_pin_state_async(dir.as_ref()))
}

pub fn save_client_pin_state_to_dir(
    dir: impl AsRef<Path>,
    state: &StoredClientPinState,
) -> Result<()> {
    block_on_store(save_client_pin_state_async(dir.as_ref(), state))
}

pub fn credentials_database_path_in_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(CREDENTIALS_DATABASE_FILE)
}

pub fn load_default_pcr_policy(dir: impl AsRef<Path>) -> Result<Option<Vec<u32>>> {
    block_on_store(load_default_pcr_policy_async(dir.as_ref()))
}

async fn load_default_pcr_policy_async(dir: &Path) -> Result<Option<Vec<u32>>> {
    let pool = open_database(dir).await?;
    let row = sqlx::query("SELECT value FROM daemon_config WHERE key = 'default_pcr_policy'")
        .fetch_optional(&pool)
        .await
        .wrap_err("loading default PCR policy from database")?;

    match row {
        Some(r) => {
            let blob: Vec<u8> = r.get("value");
            let indices: Vec<u32> = ciborium::from_reader(&blob[..])
                .wrap_err("deserializing default PCR policy from database")?;
            Ok(Some(indices))
        }
        None => Ok(None),
    }
}

pub fn save_default_pcr_policy(dir: impl AsRef<Path>, indices: &[u32]) -> Result<()> {
    block_on_store(save_default_pcr_policy_async(dir.as_ref(), indices))
}

async fn save_default_pcr_policy_async(dir: &Path, indices: &[u32]) -> Result<()> {
    let pool = open_database(dir).await?;
    let mut blob = Vec::new();
    ciborium::into_writer(indices, &mut blob).wrap_err("serializing default PCR policy")?;
    sqlx::query(
        "INSERT OR REPLACE INTO daemon_config (key, value, updated_at) VALUES ('default_pcr_policy', ?, datetime('now'))",
    )
    .bind(blob)
    .execute(&pool)
    .await
    .wrap_err("saving default PCR policy to database")?;
    Ok(())
}

async fn load_ctap2_credentials_async(
    dir: &Path,
    user_id: Option<u32>,
) -> Result<Vec<StoredCtap2Credential>> {
    let database_path = credentials_database_path_in_dir(dir);
    if !database_path.exists() {
        return Ok(Vec::new());
    }

    let pool = open_database(dir).await?;
    let rows = sqlx::query(
        "SELECT m.credential_id, m.rp_id, m.discoverable, m.user_id, m.user_handle, m.user_name, m.user_display_name, \
                m.sign_count, m.integrity_mac, \
                 p.policy_selection, p.policy_digest, p.policy_ref, p.authority_name, p.authority_signature, p.policy_version, \
                p.tpm_private AS primary_tpm_private, p.tpm_public AS primary_tpm_public, \
                p.public_key_x AS primary_public_key_x, p.public_key_y AS primary_public_key_y, \
                p.tpm_auth_value AS primary_tpm_auth_value, \
                r.slot_label AS recovery_label, \
                r.tpm_private AS recovery_tpm_private, r.tpm_public AS recovery_tpm_public, \
                r.public_key_x AS recovery_public_key_x, r.public_key_y AS recovery_public_key_y, \
                r.tpm_auth_value AS recovery_tpm_auth_value, \
                 t.passphrase_salt, t.passphrase_hash, t.kdf_algorithm, t.kdf_memory_kib, \
                 t.kdf_iterations, t.kdf_parallelism \
         FROM credential_metadata m \
         JOIN credential_keyslots p \
           ON p.credential_id = m.credential_id AND p.slot_kind = 'primary' \
         LEFT JOIN credential_keyslots r \
           ON r.credential_id = m.credential_id AND r.slot_kind = 'recovery' \
         LEFT JOIN credential_tokens t ON t.keyslot_id = r.keyslot_id \
         WHERE (?1 IS NULL OR m.user_id = ?1 OR m.user_id IS NULL) \
         ORDER BY m.rp_id, m.credential_id",
    )
    .bind(user_id.map(i64::from))
    .fetch_all(&pool)
    .await
    .wrap_err_with(|| format!("loading credentials from {}", database_path.display()))?;

    rows.into_iter()
        .map(|row| {
            let sign_count: i64 = row.try_get("sign_count")?;
            let stored_user_id: Option<i64> = row.try_get("user_id")?;
            let policy_selection: Option<String> = row.try_get("policy_selection")?;
            let policy_digest: Option<Vec<u8>> = row.try_get("policy_digest")?;
            let policy_ref: Option<Vec<u8>> = row.try_get("policy_ref")?;
            let authority_name: Option<Vec<u8>> = row.try_get("authority_name")?;
            let authority_signature: Option<Vec<u8>> = row.try_get("authority_signature")?;
            let policy_version: u32 = row
                .try_get::<i64, _>("policy_version")?
                .try_into()
                .wrap_err("invalid policy_version")?;
            let recovery_label: Option<String> = row.try_get("recovery_label")?;
            let recovery_passphrase_salt: Option<Vec<u8>> = row.try_get("passphrase_salt")?;
            let recovery_passphrase_hash: Option<Vec<u8>> = row.try_get("passphrase_hash")?;
            let recovery_kdf_algorithm: Option<String> = row.try_get("kdf_algorithm")?;
            let recovery_kdf_memory_kib: Option<i64> = row.try_get("kdf_memory_kib")?;
            let recovery_kdf_iterations: Option<i64> = row.try_get("kdf_iterations")?;
            let recovery_kdf_parallelism: Option<i64> = row.try_get("kdf_parallelism")?;
            let recovery_private: Option<Vec<u8>> = row.try_get("recovery_tpm_private")?;
            let recovery_public: Option<Vec<u8>> = row.try_get("recovery_tpm_public")?;
            let recovery_public_key_x: Option<Vec<u8>> = row.try_get("recovery_public_key_x")?;
            let recovery_public_key_y: Option<Vec<u8>> = row.try_get("recovery_public_key_y")?;
            let primary_tpm_auth_value: Option<Vec<u8>> = row.try_get("primary_tpm_auth_value")?;
            let recovery_tpm_auth_value: Option<Vec<u8>> =
                row.try_get("recovery_tpm_auth_value")?;
            let integrity_mac: Option<Vec<u8>> = row.try_get("integrity_mac")?;

            let stored = StoredCtap2Credential {
                id: row.try_get("credential_id")?,
                rp_id: row.try_get("rp_id")?,
                discoverable: row.try_get::<i64, _>("discoverable")? != 0,
                user_id: match (stored_user_id, user_id) {
                    (Some(value), _) => Some(
                        u32::try_from(value)
                            .wrap_err_with(|| format!("invalid user_id {}", value))?,
                    ),
                    (None, Some(uid)) => Some(uid),
                    (None, None) => None,
                },
                user_handle: row.try_get("user_handle")?,
                user_name: row.try_get("user_name")?,
                user_display_name: row.try_get("user_display_name")?,
                key: StoredTpmKey {
                    private: row.try_get("primary_tpm_private")?,
                    public: row.try_get("primary_tpm_public")?,
                    public_key_x: row.try_get("primary_public_key_x")?,
                    public_key_y: row.try_get("primary_public_key_y")?,
                    auth_value: primary_tpm_auth_value,
                },
                policy: match (policy_selection, policy_digest) {
                    (Some(selection), Some(digest)) => Some(StoredPcrPolicy {
                        selection,
                        digest,
                        policy_ref,
                        authority_name,
                        authority_signature,
                        policy_version,
                    }),
                    _ => None,
                },
                recovery: match (
                    recovery_label,
                    recovery_passphrase_salt,
                    recovery_passphrase_hash,
                    recovery_kdf_algorithm,
                    recovery_private,
                    recovery_public,
                    recovery_public_key_x,
                    recovery_public_key_y,
                ) {
                    (
                        label,
                        Some(passphrase_salt),
                        Some(passphrase_hash),
                        Some(kdf_algorithm),
                        Some(private),
                        Some(public),
                        Some(public_key_x),
                        Some(public_key_y),
                    ) => Some(StoredRecoverySlot {
                        label,
                        passphrase_salt,
                        passphrase_hash,
                        kdf: recovery_kdf_from_database(
                            &kdf_algorithm,
                            recovery_kdf_memory_kib,
                            recovery_kdf_iterations,
                            recovery_kdf_parallelism,
                        )?,
                        key: StoredTpmKey {
                            private,
                            public,
                            public_key_x,
                            public_key_y,
                            auth_value: recovery_tpm_auth_value,
                        },
                    }),
                    _ => None,
                },
                sign_count: u32::try_from(sign_count)
                    .wrap_err_with(|| format!("invalid sign_count {}", sign_count))?,
                integrity_mac,
            };

            if let Some(ref expected_mac) = stored.integrity_mac {
                let key = match load_or_generate_hmac_key(dir) {
                    Ok(key) => key,
                    Err(error) => {
                        log::warn!("cannot verify credential integrity: {error:?}");
                        return Ok(stored);
                    }
                };
                let computed = compute_credential_mac(&key, &stored)?;
                if computed != expected_mac as &[u8]
                    && compute_credential_mac_legacy(&key, &stored)? != expected_mac as &[u8]
                {
                    log::error!(
                        "credential integrity check failed for rp_id={} id={}",
                        stored.rp_id,
                        hex::encode(&stored.id)
                    );
                    return Err(eyre!(
                        "credential integrity check failed for rp_id={}",
                        stored.rp_id
                    ));
                }
            }

            Ok(stored)
        })
        .collect()
}

async fn save_ctap2_credentials_async(
    dir: &Path,
    credentials: &[StoredCtap2Credential],
) -> Result<()> {
    let pool = open_database(dir).await?;
    let mut tx = pool.begin().await.wrap_err("beginning store transaction")?;

    sqlx::query!("DELETE FROM credential_metadata")
        .execute(&mut *tx)
        .await
        .wrap_err("clearing credential rows")?;

    for credential in credentials {
        let key = match load_or_generate_hmac_key(dir) {
            Ok(key) => {
                let mac = compute_credential_mac(&key, credential)?;
                Some(mac)
            }
            Err(error) => {
                log::warn!("cannot compute credential integrity MAC: {error:?}");
                None
            }
        };

        sqlx::query!(
            "INSERT INTO credential_metadata \
             (credential_id, rp_id, discoverable, user_id, user_handle, user_name, user_display_name, sign_count, integrity_mac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            &credential.id,
            &credential.rp_id,
            i64::from(credential.discoverable),
            credential.user_id.map(i64::from),
            &credential.user_handle,
            credential.user_name.as_deref(),
            credential.user_display_name.as_deref(),
            i64::from(credential.sign_count),
            key.as_deref(),
        )
        .execute(&mut *tx)
        .await
        .wrap_err_with(|| format!("saving credential metadata for rp_id={}", credential.rp_id))?;

        sqlx::query!(
            "INSERT INTO credential_keyslots \
             (credential_id, slot_kind, slot_label, policy_selection, policy_digest, policy_ref, authority_name, authority_signature, policy_version, tpm_private, tpm_public, public_key_x, public_key_y, tpm_auth_value) \
             VALUES (?1, 'primary', NULL, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9, ?10, ?11)",
            &credential.id,
            credential.policy.as_ref().map(|policy| policy.selection.as_str()),
            credential.policy.as_ref().map(|policy| policy.digest.as_slice()),
            credential
                .policy
                .as_ref()
                .and_then(|policy| policy.policy_ref.as_deref()),
            credential
                .policy
                .as_ref()
                .and_then(|policy| policy.authority_name.as_deref()),
            credential
                .policy
                .as_ref()
                .and_then(|policy| policy.authority_signature.as_deref()),
            &credential.key.private,
            &credential.key.public,
            &credential.key.public_key_x,
            &credential.key.public_key_y,
            credential.key.auth_value.as_deref(),
        )
        .execute(&mut *tx)
        .await
        .wrap_err_with(|| format!("saving primary keyslot for rp_id={}", credential.rp_id))?;

        if let Some(recovery) = &credential.recovery {
            let recovery_keyslot = sqlx::query!(
                "INSERT INTO credential_keyslots \
                 (credential_id, slot_kind, slot_label, policy_selection, policy_digest, tpm_private, tpm_public, public_key_x, public_key_y, tpm_auth_value) \
                 VALUES (?1, 'recovery', ?2, NULL, NULL, ?3, ?4, ?5, ?6, ?7)",
                &credential.id,
                recovery.label.as_deref(),
                &recovery.key.private,
                &recovery.key.public,
                &recovery.key.public_key_x,
                &recovery.key.public_key_y,
                recovery.key.auth_value.as_deref(),
            )
            .execute(&mut *tx)
            .await
            .wrap_err_with(|| format!("saving recovery keyslot for rp_id={}", credential.rp_id))?;

            let (kdf_algorithm, kdf_memory_kib, kdf_iterations, kdf_parallelism) =
                recovery_kdf_database_values(&recovery.kdf);
            sqlx::query(
                "INSERT INTO credential_tokens \
                 (keyslot_id, token_type, label, passphrase_salt, passphrase_hash, \
                  kdf_algorithm, kdf_memory_kib, kdf_iterations, kdf_parallelism) \
                 VALUES (?1, 'passphrase', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(recovery_keyslot.last_insert_rowid())
            .bind(recovery.label.as_deref())
            .bind(recovery.passphrase_salt.as_slice())
            .bind(recovery.passphrase_hash.as_slice())
            .bind(kdf_algorithm)
            .bind(kdf_memory_kib)
            .bind(kdf_iterations)
            .bind(kdf_parallelism)
            .execute(&mut *tx)
            .await
            .wrap_err_with(|| format!("saving recovery token for rp_id={}", credential.rp_id))?;
        }
    }

    tx.commit()
        .await
        .wrap_err("committing credential store transaction")
}

async fn update_ctap2_sign_count_async(
    dir: &Path,
    credential_id: &[u8],
    sign_count: u32,
) -> Result<()> {
    let pool = open_database(dir).await?;
    let result = sqlx::query!(
        "UPDATE credential_metadata \
         SET sign_count = ?1, updated_at = CURRENT_TIMESTAMP \
         WHERE credential_id = ?2",
        i64::from(sign_count),
        credential_id,
    )
    .execute(&pool)
    .await
    .wrap_err("updating CTAP2 credential sign_count")?;

    if result.rows_affected() != 1 {
        return Err(eyre!(
            "updated {} rows while updating sign_count for credential ID length {}; expected 1",
            result.rows_affected(),
            credential_id.len()
        ));
    }

    Ok(())
}

async fn update_ctap2_policy_async(
    dir: &Path,
    credential_id: &[u8],
    policy: &StoredPcrPolicy,
) -> Result<()> {
    let pool = open_database(dir).await?;
    let result = sqlx::query(
        "UPDATE credential_keyslots \
         SET policy_selection = ?1, policy_digest = ?2, policy_ref = ?3, \
             authority_name = ?4, authority_signature = ?5, updated_at = CURRENT_TIMESTAMP \
         WHERE credential_id = ?6 AND slot_kind = 'primary'",
    )
    .bind(&policy.selection)
    .bind(&policy.digest)
    .bind(policy.policy_ref.as_deref())
    .bind(policy.authority_name.as_deref())
    .bind(policy.authority_signature.as_deref())
    .bind(credential_id)
    .execute(&pool)
    .await
    .wrap_err("updating CTAP2 credential PCR policy")?;

    if result.rows_affected() != 1 {
        return Err(eyre!(
            "updated {} rows while updating PCR policy for credential ID length {}; expected 1",
            result.rows_affected(),
            credential_id.len()
        ));
    }

    Ok(())
}

async fn update_recovery_slot_async(
    dir: &Path,
    credential_id: &[u8],
    new_private: &[u8],
    new_salt: &[u8],
    new_hash: &[u8],
    kdf: &RecoveryKdf,
) -> Result<()> {
    let pool = open_database(dir).await?;
    let mut tx = pool
        .begin()
        .await
        .wrap_err("beginning transaction for recovery slot update")?;

    let result = sqlx::query(
        "UPDATE credential_keyslots \
         SET tpm_private = ?1, tpm_auth_value = ?2, updated_at = CURRENT_TIMESTAMP \
         WHERE credential_id = ?3 AND slot_kind = 'recovery'",
    )
    .bind(new_private)
    .bind(new_hash)
    .bind(credential_id)
    .execute(&mut *tx)
    .await
    .wrap_err("updating recovery keyslot private blob")?;

    if result.rows_affected() != 1 {
        return Err(eyre!(
            "updated {} rows for recovery slot of credential ID length {}; expected 1",
            result.rows_affected(),
            credential_id.len()
        ));
    }

    let (kdf_algorithm, kdf_memory_kib, kdf_iterations, kdf_parallelism) =
        recovery_kdf_database_values(kdf);
    sqlx::query(
        "UPDATE credential_tokens \
          SET passphrase_salt = ?1, passphrase_hash = ?2, kdf_algorithm = ?3, \
              kdf_memory_kib = ?4, kdf_iterations = ?5, kdf_parallelism = ?6, \
              updated_at = CURRENT_TIMESTAMP \
          WHERE keyslot_id = (SELECT keyslot_id FROM credential_keyslots \
                              WHERE credential_id = ?7 AND slot_kind = 'recovery') \
           AND token_type = 'passphrase'",
    )
    .bind(new_salt)
    .bind(new_hash)
    .bind(kdf_algorithm)
    .bind(kdf_memory_kib)
    .bind(kdf_iterations)
    .bind(kdf_parallelism)
    .bind(credential_id)
    .execute(&mut *tx)
    .await
    .wrap_err("updating recovery passphrase tokens")?;

    tx.commit()
        .await
        .wrap_err("committing recovery slot update transaction")?;

    Ok(())
}

async fn delete_ctap2_credential_async(dir: &Path, credential_id: &[u8]) -> Result<()> {
    let pool = open_database(dir).await?;
    let result = sqlx::query!(
        "DELETE FROM credential_metadata WHERE credential_id = ?1",
        credential_id,
    )
    .execute(&pool)
    .await
    .wrap_err("deleting CTAP2 credential")?;
    if result.rows_affected() != 1 {
        return Err(eyre!(
            "deleted {} rows for credential ID; expected 1",
            result.rows_affected()
        ));
    }
    Ok(())
}

async fn load_client_pin_state_async(dir: &Path) -> Result<Option<StoredClientPinState>> {
    let database_path = credentials_database_path_in_dir(dir);
    if !database_path.exists() {
        return Ok(None);
    }

    let pool = open_database(dir).await?;
    let Some(row) = sqlx::query(
        "SELECT pin_salt, pin_verifier, retries, integrity_mac \
         FROM client_pin_state WHERE state_id = 1",
    )
    .fetch_optional(&pool)
    .await
    .wrap_err_with(|| format!("loading clientPIN state from {}", database_path.display()))?
    else {
        return Ok(None);
    };

    let retries: i64 = row.try_get("retries")?;
    let state = StoredClientPinState {
        pin_salt: row.try_get("pin_salt")?,
        pin_verifier: row.try_get("pin_verifier")?,
        retries: u32::try_from(retries).wrap_err("invalid clientPIN retry count")?,
        integrity_mac: row.try_get("integrity_mac")?,
    };

    if let Some(expected_mac) = &state.integrity_mac {
        let key = load_or_generate_hmac_key(dir)?;
        let computed = compute_client_pin_mac(&key, &state)?;
        if !constant_time_equal(&computed, expected_mac) {
            return Err(eyre!("clientPIN state integrity check failed"));
        }
    }

    Ok(Some(state))
}

async fn save_client_pin_state_async(dir: &Path, state: &StoredClientPinState) -> Result<()> {
    if state.pin_salt.len() != 32 || state.pin_verifier.len() != 32 || state.retries > 8 {
        return Err(eyre!("invalid clientPIN state"));
    }

    let pool = open_database(dir).await?;
    let key = load_or_generate_hmac_key(dir)?;
    let integrity_mac = compute_client_pin_mac(&key, state)?;
    sqlx::query(
        "INSERT INTO client_pin_state \
         (state_id, pin_salt, pin_verifier, retries, integrity_mac, updated_at) \
         VALUES (1, ?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)\
          ON CONFLICT(state_id) DO UPDATE SET \
            pin_salt = excluded.pin_salt, \
            pin_verifier = excluded.pin_verifier, \
            retries = excluded.retries, \
            integrity_mac = excluded.integrity_mac, \
           updated_at = CURRENT_TIMESTAMP",
    )
    .bind(&state.pin_salt)
    .bind(&state.pin_verifier)
    .bind(i64::from(state.retries))
    .bind(integrity_mac)
    .execute(&pool)
    .await
    .wrap_err("saving clientPIN state")?;

    Ok(())
}

async fn open_database(dir: &Path) -> Result<SqlitePool> {
    fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
    let database_path = credentials_database_path_in_dir(dir);
    let database_url = format!("sqlite://{}", database_path.display());
    let options = SqliteConnectOptions::from_str(&database_url)
        .wrap_err_with(|| format!("building SQLite URL for {}", database_path.display()))?
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .wrap_err_with(|| {
            format!(
                "opening SQLite credential store {}",
                database_path.display()
            )
        })?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .wrap_err_with(|| format!("running migrations for {}", database_path.display()))?;

    Ok(pool)
}

fn load_or_generate_hmac_key(dir: &Path) -> Result<[u8; 32]> {
    let path = dir.join(HMAC_KEY_FILE);
    if path.exists() {
        let raw = fs::read(&path)
            .wrap_err_with(|| format!("reading HMAC key from {}", path.display()))?;
        let key: [u8; 32] = raw.clone().try_into().map_err(|_| {
            eyre!(
                "HMAC key file {} has wrong length (expected 32, got {})",
                path.display(),
                raw.len()
            )
        })?;
        Ok(key)
    } else {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).wrap_err("generating HMAC key from system random")?;
        fs::create_dir_all(dir).wrap_err_with(|| format!("creating {}", dir.display()))?;
        fs::write(&path, key)
            .wrap_err_with(|| format!("writing HMAC key to {}", path.display()))?;
        log::info!("generated new HMAC integrity key at {}", path.display());
        Ok(key)
    }
}

fn compute_credential_mac(key: &[u8; 32], credential: &StoredCtap2Credential) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).wrap_err("creating HMAC-SHA256")?;

    mac.update(&(credential.id.len() as u64).to_be_bytes());
    mac.update(&credential.id);
    mac.update(&(credential.rp_id.len() as u64).to_be_bytes());
    mac.update(credential.rp_id.as_bytes());
    mac.update(&[u8::from(credential.discoverable)]);
    mac.update(&(credential.user_handle.len() as u64).to_be_bytes());
    mac.update(&credential.user_handle);
    mac.update(&credential.user_id.unwrap_or(0).to_be_bytes());

    let user_name = credential.user_name.as_deref().unwrap_or("");
    mac.update(&(user_name.len() as u64).to_be_bytes());
    mac.update(user_name.as_bytes());

    let display_name = credential.user_display_name.as_deref().unwrap_or("");
    mac.update(&(display_name.len() as u64).to_be_bytes());
    mac.update(display_name.as_bytes());

    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_credential_mac_legacy(
    key: &[u8; 32],
    credential: &StoredCtap2Credential,
) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).wrap_err("creating HMAC-SHA256")?;
    mac.update(&(credential.id.len() as u64).to_be_bytes());
    mac.update(&credential.id);
    mac.update(&(credential.rp_id.len() as u64).to_be_bytes());
    mac.update(credential.rp_id.as_bytes());
    mac.update(&(credential.user_handle.len() as u64).to_be_bytes());
    mac.update(&credential.user_handle);
    mac.update(&credential.user_id.unwrap_or(0).to_be_bytes());
    let user_name = credential.user_name.as_deref().unwrap_or("");
    mac.update(&(user_name.len() as u64).to_be_bytes());
    mac.update(user_name.as_bytes());
    let display_name = credential.user_display_name.as_deref().unwrap_or("");
    mac.update(&(display_name.len() as u64).to_be_bytes());
    mac.update(display_name.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_client_pin_mac(key: &[u8; 32], state: &StoredClientPinState) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).wrap_err("creating HMAC-SHA256")?;
    mac.update(&(state.pin_salt.len() as u64).to_be_bytes());
    mac.update(&state.pin_salt);
    mac.update(&(state.pin_verifier.len() as u64).to_be_bytes());
    mac.update(&state.pin_verifier);
    mac.update(&state.retries.to_be_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn block_on_store<T>(future: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .wrap_err("creating SQLite store runtime")?
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn missing_store_loads_empty_credentials() {
        let dir = test_store_dir("missing");

        let credentials = load_ctap2_credentials_from_dir(&dir, None).expect("load credentials");

        assert!(credentials.is_empty());
    }

    #[test]
    fn credentials_round_trip_through_sqlite() {
        let dir = test_store_dir("ctap2-round-trip");
        let credentials = vec![StoredCtap2Credential {
            id: vec![1, 2, 3, 4],
            rp_id: "example.com".to_owned(),
            discoverable: true,
            user_id: Some(1000),
            user_handle: vec![5, 6, 7, 8],
            user_name: Some("user".to_owned()),
            user_display_name: Some("Test User".to_owned()),
            key: StoredTpmKey {
                private: vec![9, 10],
                public: vec![11, 12],
                public_key_x: vec![13; 32],
                public_key_y: vec![14; 32],
                auth_value: None,
            },
            policy: Some(StoredPcrPolicy {
                selection: "sha256:7".to_owned(),
                digest: vec![15; 32],
                policy_ref: None,
                authority_name: None,
                authority_signature: None,
                policy_version: 1,
            }),
            recovery: Some(StoredRecoverySlot {
                label: Some("backup".to_owned()),
                passphrase_salt: vec![16; 32],
                passphrase_hash: vec![17; 32],
                kdf: RecoveryKdf::legacy_pbkdf2(),
                key: StoredTpmKey {
                    private: vec![18, 19],
                    public: vec![20, 21],
                    public_key_x: vec![22; 32],
                    public_key_y: vec![23; 32],
                    auth_value: None,
                },
            }),
            sign_count: 10,
            integrity_mac: None,
        }];

        save_ctap2_credentials_to_dir(&dir, &credentials).expect("save CTAP2 credentials");
        let loaded = load_ctap2_credentials_from_dir(&dir, None).expect("load CTAP2 credentials");

        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].integrity_mac.is_some());
        assert_eq!(loaded[0].integrity_mac.as_ref().map(Vec::len), Some(32));
        // Compare metadata excluding integrity_mac (which is computed at save time)
        let mut loaded_meta = loaded[0].clone();
        loaded_meta.integrity_mac = None;
        let mut saved_meta = credentials[0].clone();
        saved_meta.integrity_mac = None;
        assert_eq!(loaded_meta, saved_meta);
        assert!(credentials_database_path_in_dir(&dir).exists());
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn saving_replaces_removed_credentials() {
        let dir = test_store_dir("replace-removed");
        let first = StoredCtap2Credential {
            id: vec![1],
            rp_id: "first.example".to_owned(),
            discoverable: true,
            user_id: Some(1000),
            user_handle: vec![1],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![1],
                public: vec![2],
                public_key_x: vec![3; 32],
                public_key_y: vec![4; 32],
                auth_value: None,
            },
            policy: None,
            recovery: None,
            sign_count: 1,
            integrity_mac: None,
        };
        let second = StoredCtap2Credential {
            id: vec![2],
            rp_id: "second.example".to_owned(),
            discoverable: true,
            user_id: Some(1000),
            user_handle: vec![2],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![5],
                public: vec![6],
                public_key_x: vec![7; 32],
                public_key_y: vec![8; 32],
                auth_value: None,
            },
            policy: None,
            recovery: None,
            sign_count: 2,
            integrity_mac: None,
        };

        save_ctap2_credentials_to_dir(&dir, &[first, second.clone()])
            .expect("save both credentials");
        save_ctap2_credentials_to_dir(&dir, std::slice::from_ref(&second))
            .expect("save remaining credential");

        let loaded = load_ctap2_credentials_from_dir(&dir, None).expect("load credentials");

        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].integrity_mac.is_some());
        assert_eq!(loaded[0].integrity_mac.as_ref().map(Vec::len), Some(32));
        // Compare metadata excluding integrity_mac
        let mut loaded_meta = loaded[0].clone();
        loaded_meta.integrity_mac = None;
        let mut expected = second;
        expected.integrity_mac = None;
        assert_eq!(loaded_meta, expected);
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn sign_count_update_changes_one_credential() {
        let dir = test_store_dir("update-sign-count");
        let first = test_credential(vec![1], "first.example", 1);
        let second = test_credential(vec![2], "second.example", 2);
        save_ctap2_credentials_to_dir(&dir, &[first.clone(), second.clone()])
            .expect("save credentials");

        update_ctap2_sign_count_in_dir(&dir, &first.id, 42).expect("update sign count");

        let loaded = load_ctap2_credentials_from_dir(&dir, None).expect("load credentials");
        let loaded_first = loaded
            .iter()
            .find(|credential| credential.id == first.id)
            .expect("first credential");
        let loaded_second = loaded
            .iter()
            .find(|credential| credential.id == second.id)
            .expect("second credential");

        assert_eq!(loaded_first.sign_count, 42);
        assert_eq!(loaded_second.sign_count, 2);
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn sign_count_update_rejects_unknown_credential() {
        let dir = test_store_dir("update-missing-sign-count");
        save_ctap2_credentials_to_dir(&dir, &[test_credential(vec![1], "example.com", 1)])
            .expect("save credentials");

        let error =
            update_ctap2_sign_count_in_dir(&dir, &[9], 42).expect_err("reject missing credential");

        assert!(error.to_string().contains("updated 0 rows"));
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn recovery_slot_update_replaces_private_blob_and_authorization_material() {
        let dir = test_store_dir("update-recovery-slot");
        let mut credential = test_credential(vec![1], "example.com", 1);
        credential.recovery = Some(StoredRecoverySlot {
            label: Some("recovery".to_owned()),
            passphrase_salt: vec![1; 32],
            passphrase_hash: vec![2; 32],
            kdf: RecoveryKdf::legacy_pbkdf2(),
            key: StoredTpmKey {
                private: vec![3],
                public: vec![4],
                public_key_x: vec![5; 32],
                public_key_y: vec![6; 32],
                auth_value: Some(vec![2; 32]),
            },
        });
        save_ctap2_credentials_to_dir(&dir, std::slice::from_ref(&credential))
            .expect("save credential");

        update_recovery_slot_in_dir(
            &dir,
            &credential.id,
            &[7],
            &[8; 32],
            &[9; 32],
            &RecoveryKdf::argon2id_default(),
        )
        .expect("update recovery slot");

        let loaded = load_ctap2_credentials_from_dir(&dir, None).expect("load credential");
        let recovery = loaded[0].recovery.as_ref().expect("recovery slot");
        assert_eq!(recovery.key.private, vec![7]);
        assert_eq!(recovery.key.auth_value, Some(vec![9; 32]));
        assert_eq!(recovery.passphrase_salt, vec![8; 32]);
        assert_eq!(recovery.passphrase_hash, vec![9; 32]);
        assert_eq!(recovery.kdf, RecoveryKdf::argon2id_default());
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn pcr_policy_version_support() {
        assert!(StoredPcrPolicy::is_version_supported(
            StoredPcrPolicy::current_version()
        ));
        assert!(!StoredPcrPolicy::is_version_supported(0));
        assert!(!StoredPcrPolicy::is_version_supported(2));
        assert!(!StoredPcrPolicy::is_version_supported(99));
    }

    fn test_credential(id: Vec<u8>, rp_id: &str, sign_count: u32) -> StoredCtap2Credential {
        StoredCtap2Credential {
            id,
            rp_id: rp_id.to_owned(),
            discoverable: true,
            user_id: Some(1000),
            user_handle: vec![1, 2, 3, 4],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![5],
                public: vec![6],
                public_key_x: vec![7; 32],
                public_key_y: vec![8; 32],
                auth_value: None,
            },
            policy: None,
            recovery: None,
            sign_count,
            integrity_mac: None,
        }
    }

    fn test_store_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "linux-tpm-fido2-store-test-{name}-{}-{nonce}",
            std::process::id()
        ))
    }
}
