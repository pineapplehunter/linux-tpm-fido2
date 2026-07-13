use std::{fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use color_eyre::{eyre::WrapErr, Result};
use serde::{Deserialize, Serialize};

pub const DEV_STORE_DIR: &str = ".linux-tpm-fido2-store";
const U2F_CREDENTIALS_FILE: &str = "u2f-credentials.json";

#[derive(Debug, Clone)]
pub struct StoredU2fCredential {
    pub key_handle: Vec<u8>,
    pub application: [u8; 32],
    pub private_key: Vec<u8>,
    pub counter: u32,
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

pub fn dev_store_dir() -> PathBuf {
    PathBuf::from(DEV_STORE_DIR)
}

pub fn load_u2f_credentials() -> Result<Vec<StoredU2fCredential>> {
    let path = u2f_credentials_path();
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
    let dir = dev_store_dir();
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

    let path = u2f_credentials_path();
    let data = serde_json::to_string_pretty(&file).wrap_err("serializing U2F credential store")?;
    fs::write(&path, data).wrap_err_with(|| format!("writing {}", path.display()))
}

fn u2f_credentials_path() -> PathBuf {
    dev_store_dir().join(U2F_CREDENTIALS_FILE)
}

fn decode_field(value: &str, name: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .wrap_err_with(|| format!("decoding base64 field {name}"))
}
