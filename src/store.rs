use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use color_eyre::{Result, eyre::WrapErr};
use serde::{Deserialize, Serialize};

pub const DEV_STORE_DIR: &str = ".linux-tpm-fido2-store";
const CTAP2_CREDENTIALS_FILE: &str = "ctap2-credentials.json";

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

#[derive(Debug, Serialize, Deserialize)]
struct Ctap2CredentialFile {
    version: u32,
    credentials: Vec<Ctap2CredentialRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ctap2CredentialRecord {
    id: String,
    rp_id: String,
    user_handle: String,
    user_name: Option<String>,
    user_display_name: Option<String>,
    tpm_private: String,
    tpm_public: String,
    public_key_x: String,
    public_key_y: String,
    sign_count: u32,
}

pub fn dev_store_dir() -> PathBuf {
    PathBuf::from(DEV_STORE_DIR)
}

pub fn ctap2_credentials_path() -> PathBuf {
    ctap2_credentials_path_in_dir(dev_store_dir())
}

pub fn load_ctap2_credentials() -> Result<Vec<StoredCtap2Credential>> {
    load_ctap2_credentials_from_dir(dev_store_dir())
}

pub fn load_ctap2_credentials_from_dir(
    dir: impl AsRef<Path>,
) -> Result<Vec<StoredCtap2Credential>> {
    let path = ctap2_credentials_path_in_dir(dir);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = fs::read_to_string(&path).wrap_err_with(|| format!("reading {}", path.display()))?;
    let file: Ctap2CredentialFile =
        serde_json::from_str(&data).wrap_err_with(|| format!("parsing {}", path.display()))?;

    file.credentials
        .into_iter()
        .map(|record| {
            Ok(StoredCtap2Credential {
                id: decode_field(&record.id, "id")?,
                rp_id: record.rp_id,
                user_handle: decode_field(&record.user_handle, "user_handle")?,
                user_name: record.user_name,
                user_display_name: record.user_display_name,
                key: StoredTpmKey {
                    private: decode_field(&record.tpm_private, "tpm_private")?,
                    public: decode_field(&record.tpm_public, "tpm_public")?,
                    public_key_x: decode_field(&record.public_key_x, "public_key_x")?,
                    public_key_y: decode_field(&record.public_key_y, "public_key_y")?,
                },
                sign_count: record.sign_count,
            })
        })
        .collect()
}

pub fn save_ctap2_credentials(credentials: &[StoredCtap2Credential]) -> Result<()> {
    save_ctap2_credentials_to_dir(dev_store_dir(), credentials)
}

pub fn save_ctap2_credentials_to_dir(
    dir: impl AsRef<Path>,
    credentials: &[StoredCtap2Credential],
) -> Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(&dir).wrap_err_with(|| format!("creating {}", dir.display()))?;

    let file = Ctap2CredentialFile {
        version: 1,
        credentials: credentials
            .iter()
            .map(|credential| Ctap2CredentialRecord {
                id: STANDARD.encode(&credential.id),
                rp_id: credential.rp_id.clone(),
                user_handle: STANDARD.encode(&credential.user_handle),
                user_name: credential.user_name.clone(),
                user_display_name: credential.user_display_name.clone(),
                tpm_private: STANDARD.encode(&credential.key.private),
                tpm_public: STANDARD.encode(&credential.key.public),
                public_key_x: STANDARD.encode(&credential.key.public_key_x),
                public_key_y: STANDARD.encode(&credential.key.public_key_y),
                sign_count: credential.sign_count,
            })
            .collect(),
    };

    let path = ctap2_credentials_path_in_dir(dir);
    let data =
        serde_json::to_string_pretty(&file).wrap_err("serializing CTAP2 credential store")?;
    fs::write(&path, data).wrap_err_with(|| format!("writing {}", path.display()))
}

pub fn ctap2_credentials_path_in_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(CTAP2_CREDENTIALS_FILE)
}

fn decode_field(value: &str, name: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .wrap_err_with(|| format!("decoding base64 field {name}"))
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
    fn credentials_round_trip_as_json() {
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
        fs::remove_dir_all(&dir).expect("remove test store");
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
