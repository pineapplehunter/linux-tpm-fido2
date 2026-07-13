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
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

pub const DEV_STORE_DIR: &str = ".linux-tpm-fido2-store";
const CREDENTIALS_DATABASE_FILE: &str = "credentials.sqlite";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCtap2Credential {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub key: StoredTpmKey,
    pub sign_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTpmKey {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
}

pub fn dev_store_dir() -> PathBuf {
    PathBuf::from(DEV_STORE_DIR)
}

pub fn credentials_database_path() -> PathBuf {
    credentials_database_path_in_dir(dev_store_dir())
}

pub fn load_ctap2_credentials() -> Result<Vec<StoredCtap2Credential>> {
    load_ctap2_credentials_from_dir(dev_store_dir())
}

pub fn load_ctap2_credentials_from_dir(
    dir: impl AsRef<Path>,
) -> Result<Vec<StoredCtap2Credential>> {
    block_on_store(load_ctap2_credentials_async(dir.as_ref()))
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

pub fn credentials_database_path_in_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(CREDENTIALS_DATABASE_FILE)
}

async fn load_ctap2_credentials_async(dir: &Path) -> Result<Vec<StoredCtap2Credential>> {
    let database_path = credentials_database_path_in_dir(dir);
    if !database_path.exists() {
        return Ok(Vec::new());
    }

    let pool = open_database(dir).await?;
    let rows = sqlx::query(
        "SELECT c.credential_id, c.rp_id, c.user_handle, c.user_name, c.user_display_name, \
                c.sign_count, k.tpm_private, k.tpm_public, k.public_key_x, k.public_key_y \
         FROM credentials c \
         JOIN tpm_keys k ON k.credential_id = c.credential_id \
         ORDER BY c.rp_id, c.credential_id",
    )
    .fetch_all(&pool)
    .await
    .wrap_err_with(|| format!("loading credentials from {}", database_path.display()))?;

    rows.into_iter()
        .map(|row| {
            let sign_count: i64 = row.try_get("sign_count")?;
            Ok(StoredCtap2Credential {
                id: row.try_get("credential_id")?,
                rp_id: row.try_get("rp_id")?,
                user_handle: row.try_get("user_handle")?,
                user_name: row.try_get("user_name")?,
                user_display_name: row.try_get("user_display_name")?,
                key: StoredTpmKey {
                    private: row.try_get("tpm_private")?,
                    public: row.try_get("tpm_public")?,
                    public_key_x: row.try_get("public_key_x")?,
                    public_key_y: row.try_get("public_key_y")?,
                },
                sign_count: u32::try_from(sign_count)
                    .wrap_err_with(|| format!("invalid sign_count {sign_count}"))?,
            })
        })
        .collect()
}

async fn save_ctap2_credentials_async(
    dir: &Path,
    credentials: &[StoredCtap2Credential],
) -> Result<()> {
    let pool = open_database(dir).await?;
    let mut tx = pool.begin().await.wrap_err("beginning store transaction")?;

    sqlx::query("DELETE FROM tpm_keys")
        .execute(&mut *tx)
        .await
        .wrap_err("clearing TPM key rows")?;
    sqlx::query("DELETE FROM credentials")
        .execute(&mut *tx)
        .await
        .wrap_err("clearing credential rows")?;

    for credential in credentials {
        sqlx::query(
            "INSERT INTO credentials \
             (credential_id, rp_id, user_handle, user_name, user_display_name, sign_count) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&credential.id)
        .bind(&credential.rp_id)
        .bind(&credential.user_handle)
        .bind(&credential.user_name)
        .bind(&credential.user_display_name)
        .bind(i64::from(credential.sign_count))
        .execute(&mut *tx)
        .await
        .wrap_err_with(|| format!("saving credential for rp_id={}", credential.rp_id))?;

        sqlx::query(
            "INSERT INTO tpm_keys \
             (credential_id, tpm_private, tpm_public, public_key_x, public_key_y) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&credential.id)
        .bind(&credential.key.private)
        .bind(&credential.key.public)
        .bind(&credential.key.public_key_x)
        .bind(&credential.key.public_key_y)
        .execute(&mut *tx)
        .await
        .wrap_err_with(|| format!("saving TPM key for rp_id={}", credential.rp_id))?;
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
    let result = sqlx::query(
        "UPDATE credentials \
         SET sign_count = ?1, updated_at = CURRENT_TIMESTAMP \
         WHERE credential_id = ?2",
    )
    .bind(i64::from(sign_count))
    .bind(credential_id)
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

        let credentials = load_ctap2_credentials_from_dir(&dir).expect("load credentials");

        assert!(credentials.is_empty());
    }

    #[test]
    fn credentials_round_trip_through_sqlite() {
        let dir = test_store_dir("ctap2-round-trip");
        let credentials = vec![StoredCtap2Credential {
            id: vec![1, 2, 3, 4],
            rp_id: "example.com".to_owned(),
            user_handle: vec![5, 6, 7, 8],
            user_name: Some("user".to_owned()),
            user_display_name: Some("Test User".to_owned()),
            key: StoredTpmKey {
                private: vec![9, 10],
                public: vec![11, 12],
                public_key_x: vec![13; 32],
                public_key_y: vec![14; 32],
            },
            sign_count: 10,
        }];

        save_ctap2_credentials_to_dir(&dir, &credentials).expect("save CTAP2 credentials");
        let loaded = load_ctap2_credentials_from_dir(&dir).expect("load CTAP2 credentials");

        assert_eq!(loaded, credentials);
        assert!(credentials_database_path_in_dir(&dir).exists());
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn saving_replaces_removed_credentials() {
        let dir = test_store_dir("replace-removed");
        let first = StoredCtap2Credential {
            id: vec![1],
            rp_id: "first.example".to_owned(),
            user_handle: vec![1],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![1],
                public: vec![2],
                public_key_x: vec![3; 32],
                public_key_y: vec![4; 32],
            },
            sign_count: 1,
        };
        let second = StoredCtap2Credential {
            id: vec![2],
            rp_id: "second.example".to_owned(),
            user_handle: vec![2],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![5],
                public: vec![6],
                public_key_x: vec![7; 32],
                public_key_y: vec![8; 32],
            },
            sign_count: 2,
        };

        save_ctap2_credentials_to_dir(&dir, &[first, second.clone()])
            .expect("save both credentials");
        save_ctap2_credentials_to_dir(&dir, std::slice::from_ref(&second))
            .expect("save remaining credential");

        let loaded = load_ctap2_credentials_from_dir(&dir).expect("load credentials");

        assert_eq!(loaded, vec![second]);
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

        let loaded = load_ctap2_credentials_from_dir(&dir).expect("load credentials");
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

    fn test_credential(id: Vec<u8>, rp_id: &str, sign_count: u32) -> StoredCtap2Credential {
        StoredCtap2Credential {
            id,
            rp_id: rp_id.to_owned(),
            user_handle: vec![1, 2, 3, 4],
            user_name: None,
            user_display_name: None,
            key: StoredTpmKey {
                private: vec![5],
                public: vec![6],
                public_key_x: vec![7; 32],
                public_key_y: vec![8; 32],
            },
            sign_count,
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
