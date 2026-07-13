use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use color_eyre::{Result, eyre::WrapErr};
use serde::{Deserialize, Serialize};

pub const DEV_STORE_DIR: &str = ".linux-tpm-fido2-store";
const U2F_CREDENTIALS_FILE: &str = "u2f-credentials.json";
const CTAP2_CREDENTIALS_FILE: &str = "ctap2-credentials.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredU2fCredential {
    pub key_handle: Vec<u8>,
    pub application: [u8; 32],
    pub private_key: Vec<u8>,
    pub counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCtap2Credential {
    pub id: Vec<u8>,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub private_key: Vec<u8>,
    pub sign_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct U2fCredentialFile {
    version: u32,
    credentials: Vec<U2fCredentialRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
struct U2fCredentialRecord {
    key_handle: String,
    application: String,
    private_key: String,
    counter: u32,
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
    private_key: String,
    sign_count: u32,
}

pub fn dev_store_dir() -> PathBuf {
    PathBuf::from(DEV_STORE_DIR)
}

pub fn load_u2f_credentials() -> Result<Vec<StoredU2fCredential>> {
    load_u2f_credentials_from_dir(dev_store_dir())
}

pub fn u2f_credentials_path() -> PathBuf {
    u2f_credentials_path_in_dir(dev_store_dir())
}

pub fn ctap2_credentials_path() -> PathBuf {
    ctap2_credentials_path_in_dir(dev_store_dir())
}

pub fn load_u2f_credentials_from_dir(dir: impl AsRef<Path>) -> Result<Vec<StoredU2fCredential>> {
    let path = u2f_credentials_path_in_dir(dir);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = fs::read_to_string(&path).wrap_err_with(|| format!("reading {}", path.display()))?;
    let file: U2fCredentialFile =
        serde_json::from_str(&data).wrap_err_with(|| format!("parsing {}", path.display()))?;

    file.credentials
        .into_iter()
        .map(|record| {
            let application = decode_field(&record.application, "application")?;
            let application: [u8; 32] = application
                .try_into()
                .map_err(|_| color_eyre::eyre::eyre!("stored U2F application must be 32 bytes"))?;
            Ok(StoredU2fCredential {
                key_handle: decode_field(&record.key_handle, "key_handle")?,
                application,
                private_key: decode_field(&record.private_key, "private_key")?,
                counter: record.counter,
            })
        })
        .collect()
}

pub fn save_u2f_credentials(credentials: &[StoredU2fCredential]) -> Result<()> {
    save_u2f_credentials_to_dir(dev_store_dir(), credentials)
}

pub fn save_u2f_credentials_to_dir(
    dir: impl AsRef<Path>,
    credentials: &[StoredU2fCredential],
) -> Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(&dir).wrap_err_with(|| format!("creating {}", dir.display()))?;

    let file = U2fCredentialFile {
        version: 1,
        credentials: credentials
            .iter()
            .map(|credential| U2fCredentialRecord {
                key_handle: STANDARD.encode(&credential.key_handle),
                application: STANDARD.encode(credential.application),
                private_key: STANDARD.encode(&credential.private_key),
                counter: credential.counter,
            })
            .collect(),
    };

    let path = u2f_credentials_path_in_dir(dir);
    let data = serde_json::to_string_pretty(&file).wrap_err("serializing U2F credential store")?;
    fs::write(&path, data).wrap_err_with(|| format!("writing {}", path.display()))
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
                private_key: decode_field(&record.private_key, "private_key")?,
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
                private_key: STANDARD.encode(&credential.private_key),
                sign_count: credential.sign_count,
            })
            .collect(),
    };

    let path = ctap2_credentials_path_in_dir(dir);
    let data =
        serde_json::to_string_pretty(&file).wrap_err("serializing CTAP2 credential store")?;
    fs::write(&path, data).wrap_err_with(|| format!("writing {}", path.display()))
}

pub fn u2f_credentials_path_in_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(U2F_CREDENTIALS_FILE)
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

        let credentials = load_u2f_credentials_from_dir(&dir).expect("load credentials");

        assert!(credentials.is_empty());
    }

    #[test]
    fn credentials_round_trip_as_json() {
        let dir = test_store_dir("round-trip");
        let credentials = vec![StoredU2fCredential {
            key_handle: vec![1, 2, 3, 4],
            application: [5; 32],
            private_key: vec![6; 32],
            counter: 7,
        }];

        save_u2f_credentials_to_dir(&dir, &credentials).expect("save credentials");
        let loaded = load_u2f_credentials_from_dir(&dir).expect("load credentials");

        assert_eq!(loaded, credentials);
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn ctap2_credentials_round_trip_as_json() {
        let dir = test_store_dir("ctap2-round-trip");
        let credentials = vec![StoredCtap2Credential {
            id: vec![1, 2, 3, 4],
            rp_id: "example.com".to_owned(),
            user_handle: vec![5, 6, 7, 8],
            user_name: Some("user".to_owned()),
            user_display_name: Some("Test User".to_owned()),
            private_key: vec![9; 32],
            sign_count: 10,
        }];

        save_ctap2_credentials_to_dir(&dir, &credentials).expect("save CTAP2 credentials");
        let loaded = load_ctap2_credentials_from_dir(&dir).expect("load CTAP2 credentials");

        assert_eq!(loaded, credentials);
        fs::remove_dir_all(&dir).expect("remove test store");
    }

    #[test]
    fn invalid_application_length_is_rejected() {
        let dir = test_store_dir("invalid-application");
        fs::create_dir_all(&dir).expect("create test store");
        fs::write(
            u2f_credentials_path_in_dir(&dir),
            r#"{
  "version": 1,
  "credentials": [
    {
      "key_handle": "AQIDBA==",
      "application": "BQY=",
      "private_key": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
      "counter": 9
    }
  ]
}"#,
        )
        .expect("write invalid store");

        let error = load_u2f_credentials_from_dir(&dir).expect_err("invalid application length");

        assert!(error.to_string().contains("application must be 32 bytes"));
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
