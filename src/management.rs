use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use color_eyre::Result;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{ctap2, store, tpm};

/// Returns the well-known path for the management Unix socket.
pub fn management_socket_path() -> PathBuf {
    PathBuf::from("/run/linux-tpm-fido2/management.sock")
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "params")]
pub enum ManagementRequest {
    #[serde(rename = "list-credentials")]
    ListCredentials,
    #[serde(rename = "update-passphrase")]
    UpdatePassphrase {
        old_passphrase: String,
        new_passphrase: String,
    },
    #[serde(rename = "update-pcr-reference")]
    UpdatePcrReference { passphrase: String },
    #[serde(rename = "update-pcr-policy")]
    UpdatePcrPolicy {
        passphrase: String,
        pcr_indices: Vec<u32>,
        #[serde(flatten)]
        credential_target: CredentialTarget,
    },
    #[serde(rename = "set-default-pcr-policy")]
    SetDefaultPcrPolicy { pcr_indices: Vec<u32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialTarget {
    All { all: bool },
    Ids { credential_ids: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManagementResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

fn recv_message(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn send_message(stream: &mut UnixStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

fn handle_list_credentials(store_dir: &Path, _tpm_path: &Path) -> ManagementResponse {
    match store::load_ctap2_credentials_from_dir(store_dir, None) {
        Ok(credentials) => {
            let creds: Vec<serde_json::Value> = credentials
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": hex::encode(&c.id),
                        "rp_id": c.rp_id,
                        "user_name": c.user_name,
                        "discoverable": c.discoverable,
                    })
                })
                .collect();
            ManagementResponse {
                ok: true,
                error: None,
                result: Some(serde_json::json!({ "credentials": creds })),
            }
        }
        Err(e) => ManagementResponse {
            ok: false,
            error: Some(format!("{e}")),
            result: None,
        },
    }
}

fn handle_update_passphrase(
    store_dir: &Path,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    old_passphrase: &str,
    new_passphrase: &str,
) -> ManagementResponse {
    let credentials = match store::load_ctap2_credentials_from_dir(store_dir, None) {
        Ok(c) => c,
        Err(e) => {
            return ManagementResponse {
                ok: false,
                error: Some(format!("{e}")),
                result: None,
            };
        }
    };

    let mut results = Vec::new();
    for credential in &credentials {
        let id_hex = hex::encode(&credential.id);
        let recovery = match credential.recovery.as_ref() {
            Some(r) => r,
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "skipped",
                    "reason": "no recovery slot"
                }));
                continue;
            }
        };

        // Validate old passphrase (no TPM needed).
        let mut old_hash = match tpm::recovery_passphrase_hash(
            &recovery.kdf,
            &recovery.passphrase_salt,
            old_passphrase,
        ) {
            Ok(h) => h,
            Err(e) => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": format!("passphrase validation error: {e}")
                }));
                continue;
            }
        };
        if old_hash != recovery.passphrase_hash {
            old_hash.zeroize();
            results.push(serde_json::json!({
                "credential": id_hex,
                "status": "error",
                "error": "recovery passphrase does not match"
            }));
            continue;
        }
        old_hash.zeroize();

        // Generate new salt and hash (no TPM needed).
        let mut new_salt = vec![0u8; 32];
        if getrandom::fill(&mut new_salt).is_err() {
            results.push(serde_json::json!({
                "credential": id_hex,
                "status": "error",
                "error": "failed to generate random salt"
            }));
            continue;
        }
        let new_kdf = tpm::RecoveryKdf::argon2id_default();
        let new_hash = match tpm::recovery_passphrase_hash(&new_kdf, &new_salt, new_passphrase) {
            Ok(h) => h,
            Err(e) => {
                new_salt.zeroize();
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": format!("new passphrase hash error: {e}")
                }));
                continue;
            }
        };

        let recovery_key = tpm::TpmCredential {
            private: recovery.key.private.clone(),
            public: recovery.key.public.clone(),
            public_key_x: recovery.key.public_key_x.clone(),
            public_key_y: recovery.key.public_key_y.clone(),
            auth_value: recovery.key.auth_value.clone(),
        };

        // Send TPM operation to main thread, or fall back to direct open.
        let cmd_result = if let Some(tx) = tpm_cmd_tx {
            let (resp_tx, resp_rx) = mpsc::channel();
            let cmd = ctap2::TpmCommand::PassphraseChange(ctap2::PassphraseChangeCommand {
                credential_id: credential.id.clone(),
                recovery_key,
                new_passphrase_hash: new_hash.clone(),
                new_salt: new_salt.clone(),
                new_kdf: new_kdf.clone(),
            });
            if tx.send((cmd, resp_tx)).is_ok() {
                match resp_rx.recv() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(color_eyre::eyre::eyre!("{e}")),
                    Err(_) => Err(color_eyre::eyre::eyre!("TPM command channel closed")),
                }
            } else {
                Err(color_eyre::eyre::eyre!("failed to send TPM command"))
            }
        } else {
            // Fallback: open TPM directly (for testing without daemon).
            ctap2::change_recovery_passphrase(
                store_dir,
                Some(Path::new("/dev/tpmrm0")),
                &credential.id,
                old_passphrase,
                new_passphrase,
            )
        };

        new_salt.zeroize();
        match cmd_result {
            Ok(()) => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "ok"
                }));
            }
            Err(e) => {
                log::warn!("failed to change passphrase for {id_hex}: {e}");
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": format!("{e}")
                }));
            }
        }
    }

    ManagementResponse {
        ok: true,
        error: None,
        result: Some(serde_json::json!({ "results": results })),
    }
}

fn handle_update_pcr_reference(
    store_dir: &Path,
    passphrase: &str,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
) -> ManagementResponse {
    let credentials = match store::load_ctap2_credentials_from_dir(store_dir, None) {
        Ok(c) => c,
        Err(e) => {
            return ManagementResponse {
                ok: false,
                error: Some(format!("{e}")),
                result: None,
            };
        }
    };

    let mut results = Vec::new();
    for credential in &credentials {
        let id_hex = hex::encode(&credential.id);
        let policy = match credential.policy.as_ref() {
            Some(p) => p,
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "skipped",
                    "reason": "no PCR policy"
                }));
                continue;
            }
        };
        let recovery = match credential.recovery.as_ref() {
            Some(r) => r,
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "skipped",
                    "reason": "no recovery slot"
                }));
                continue;
            }
        };
        let policy_ref = match policy.policy_ref.as_ref() {
            Some(r) => r.clone(),
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": "credential has no policyRef"
                }));
                continue;
            }
        };
        let authority_name = match policy.authority_name.as_ref() {
            Some(n) => n.clone(),
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": "credential has no authority name"
                }));
                continue;
            }
        };

        // Validate recovery passphrase (no TPM needed).
        let passphrase_result =
            tpm::recovery_passphrase_hash(&recovery.kdf, &recovery.passphrase_salt, passphrase);
        match passphrase_result {
            Ok(hash) => {
                if hash != recovery.passphrase_hash {
                    results.push(serde_json::json!({
                        "credential": id_hex,
                        "status": "error",
                        "error": "recovery passphrase does not match"
                    }));
                    continue;
                }
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": format!("passphrase validation error: {e}")
                }));
                continue;
            }
        }

        let authority = tpm::TpmCredential {
            private: recovery.key.private.clone(),
            public: recovery.key.public.clone(),
            public_key_x: recovery.key.public_key_x.clone(),
            public_key_y: recovery.key.public_key_y.clone(),
            auth_value: recovery.key.auth_value.clone(),
        };

        // Send TPM operation to main thread, or fall back to direct open.
        let cmd_result = if let Some(tx) = tpm_cmd_tx {
            let (resp_tx, resp_rx) = mpsc::channel();
            let cmd = ctap2::TpmCommand::PcrPolicyUpdate(ctap2::PcrPolicyUpdateCommand {
                credential_id: credential.id.clone(),
                authority,
                authority_name,
                policy_ref,
            });
            if tx.send((cmd, resp_tx)).is_ok() {
                match resp_rx.recv() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(color_eyre::eyre::eyre!("{e}")),
                    Err(_) => Err(color_eyre::eyre::eyre!("TPM command channel closed")),
                }
            } else {
                Err(color_eyre::eyre::eyre!("failed to send TPM command"))
            }
        } else {
            // Fallback: open TPM directly (for testing without daemon).
            ctap2::update_pcr_policy_for_credential(store_dir, None, &credential.id, passphrase)
        };

        match cmd_result {
            Ok(()) => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "ok"
                }));
            }
            Err(e) => {
                log::warn!("failed to update PCR policy for {id_hex}: {e}");
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": format!("{e}")
                }));
            }
        }
    }

    ManagementResponse {
        ok: true,
        error: None,
        result: Some(serde_json::json!({ "results": results })),
    }
}

fn handle_update_pcr_policy(
    store_dir: &Path,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    passphrase: &str,
    _pcr_indices: &[u32],
    credential_target: &CredentialTarget,
) -> ManagementResponse {
    let credentials = match store::load_ctap2_credentials_from_dir(store_dir, None) {
        Ok(c) => c,
        Err(e) => {
            return ManagementResponse {
                ok: false,
                error: Some(format!("{e}")),
                result: None,
            };
        }
    };

    let ids: Vec<Vec<u8>> = match credential_target {
        CredentialTarget::All { all: true } => credentials.iter().map(|c| c.id.clone()).collect(),
        CredentialTarget::All { all: false } => {
            return ManagementResponse {
                ok: false,
                error: Some("--all must be explicitly set to true".into()),
                result: None,
            };
        }
        CredentialTarget::Ids { credential_ids } => {
            match credential_ids
                .iter()
                .map(hex::decode)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(ids) => ids,
                Err(e) => {
                    return ManagementResponse {
                        ok: false,
                        error: Some(format!("invalid hex credential ID: {e}")),
                        result: None,
                    };
                }
            }
        }
    };

    let mut results = Vec::new();

    for id in &ids {
        let id_hex = hex::encode(id);
        let credential = match credentials.iter().find(|c| c.id == *id) {
            Some(c) => c,
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "skipped",
                    "reason": "credential not found"
                }));
                continue;
            }
        };

        let policy = match credential.policy.as_ref() {
            Some(p) => p,
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "skipped",
                    "reason": "no PCR policy"
                }));
                continue;
            }
        };
        let recovery = match credential.recovery.as_ref() {
            Some(r) => r,
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "skipped",
                    "reason": "no recovery slot"
                }));
                continue;
            }
        };
        let policy_ref = match policy.policy_ref.as_ref() {
            Some(r) => r.clone(),
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": "credential has no policyRef"
                }));
                continue;
            }
        };
        let authority_name = match policy.authority_name.as_ref() {
            Some(n) => n.clone(),
            None => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": "credential has no authority name"
                }));
                continue;
            }
        };

        // Validate passphrase (no TPM needed).
        let mut passphrase_hash = match tpm::recovery_passphrase_hash(
            &recovery.kdf,
            &recovery.passphrase_salt,
            passphrase,
        ) {
            Ok(h) => h,
            Err(e) => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": format!("passphrase validation error: {e}")
                }));
                continue;
            }
        };
        let passphrase_ok = passphrase_hash == recovery.passphrase_hash;
        passphrase_hash.zeroize();
        if !passphrase_ok {
            results.push(serde_json::json!({
                "credential": id_hex,
                "status": "error",
                "error": "recovery passphrase does not match"
            }));
            continue;
        }

        let authority = tpm::TpmCredential {
            private: recovery.key.private.clone(),
            public: recovery.key.public.clone(),
            public_key_x: recovery.key.public_key_x.clone(),
            public_key_y: recovery.key.public_key_y.clone(),
            auth_value: recovery.key.auth_value.clone(),
        };

        // Send TPM operation to main thread, or fall back to direct open.
        let cmd_result = if let Some(tx) = tpm_cmd_tx {
            let (resp_tx, resp_rx) = mpsc::channel();
            let cmd = ctap2::TpmCommand::PcrPolicyUpdate(ctap2::PcrPolicyUpdateCommand {
                credential_id: id.clone(),
                authority,
                authority_name,
                policy_ref,
            });
            if tx.send((cmd, resp_tx)).is_ok() {
                match resp_rx.recv() {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(color_eyre::eyre::eyre!("{e}")),
                    Err(_) => Err(color_eyre::eyre::eyre!("TPM command channel closed")),
                }
            } else {
                Err(color_eyre::eyre::eyre!("failed to send TPM command"))
            }
        } else {
            // Fallback: open TPM directly (for testing without daemon).
            ctap2::update_pcr_policy_for_credential(
                store_dir,
                Some(Path::new("/dev/tpmrm0")),
                id,
                passphrase,
            )
        };

        match cmd_result {
            Ok(()) => {
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "ok"
                }));
            }
            Err(e) => {
                log::warn!("failed to update PCR policy for {id_hex}: {e}");
                results.push(serde_json::json!({
                    "credential": id_hex,
                    "status": "error",
                    "error": format!("{e}")
                }));
            }
        }
    }

    ManagementResponse {
        ok: true,
        error: None,
        result: Some(serde_json::json!({ "results": results })),
    }
}

fn handle_set_default_pcr_policy(store_dir: &Path, pcr_indices: &[u32]) -> ManagementResponse {
    match store::save_default_pcr_policy(store_dir, pcr_indices) {
        Ok(()) => ManagementResponse {
            ok: true,
            error: None,
            result: Some(serde_json::json!({ "pcr_indices": pcr_indices })),
        },
        Err(e) => ManagementResponse {
            ok: false,
            error: Some(format!("{e}")),
            result: None,
        },
    }
}

fn dispatch(
    store_dir: &Path,
    tpm_cmd_tx: Option<&ctap2::TpmCmdSender>,
    request: &ManagementRequest,
) -> ManagementResponse {
    match request {
        ManagementRequest::ListCredentials => handle_list_credentials(store_dir, Path::new("")),
        ManagementRequest::UpdatePassphrase {
            old_passphrase,
            new_passphrase,
        } => handle_update_passphrase(store_dir, tpm_cmd_tx, old_passphrase, new_passphrase),
        ManagementRequest::UpdatePcrReference { passphrase } => {
            handle_update_pcr_reference(store_dir, passphrase, tpm_cmd_tx)
        }
        ManagementRequest::UpdatePcrPolicy {
            passphrase,
            pcr_indices,
            credential_target,
        } => handle_update_pcr_policy(
            store_dir,
            tpm_cmd_tx,
            passphrase,
            pcr_indices,
            credential_target,
        ),
        ManagementRequest::SetDefaultPcrPolicy { pcr_indices } => {
            handle_set_default_pcr_policy(store_dir, pcr_indices)
        }
    }
}

fn handle_client(
    mut stream: UnixStream,
    store_dir: PathBuf,
    tpm_cmd_tx: Option<ctap2::TpmCmdSender>,
) {
    let data = match recv_message(&mut stream) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("management: failed to read request: {e}");
            return;
        }
    };

    let request: ManagementRequest = match serde_json::from_slice(&data) {
        Ok(r) => r,
        Err(e) => {
            let resp = ManagementResponse {
                ok: false,
                error: Some(format!("invalid request: {e}")),
                result: None,
            };
            if let Ok(encoded) = serde_json::to_vec(&resp) {
                let _ = send_message(&mut stream, &encoded);
            }
            return;
        }
    };

    let response = dispatch(&store_dir, tpm_cmd_tx.as_ref(), &request);
    let encoded = match serde_json::to_vec(&response) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("management: failed to encode response: {e}");
            return;
        }
    };
    if let Err(e) = send_message(&mut stream, &encoded) {
        log::warn!("management: failed to send response: {e}");
    }
}

pub fn serve(
    store_dir: PathBuf,
    tpm_cmd_tx: Option<ctap2::TpmCmdSender>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let socket_path = management_socket_path();

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).map_err(|e| {
        color_eyre::eyre::eyre!("binding management socket at {socket_path:?}: {e}")
    })?;

    log::info!("management socket at {}", socket_path.display());

    listener.set_nonblocking(true)?;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((stream, addr)) => {
                log::debug!("management: connection from {addr:?}");
                let store_dir = store_dir.clone();
                let tpm_cmd_tx = tpm_cmd_tx.clone();
                std::thread::spawn(move || {
                    handle_client(stream, store_dir, tpm_cmd_tx);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                log::warn!("management: accept error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

pub fn send_request(request: &ManagementRequest) -> Result<ManagementResponse> {
    let socket_path = management_socket_path();

    let mut stream = UnixStream::connect(&socket_path).map_err(|e| {
        color_eyre::eyre::eyre!(
            "connecting to daemon at {socket_path:?}: {e}. Is the daemon running?"
        )
    })?;

    let encoded = serde_json::to_vec(request)
        .map_err(|e| color_eyre::eyre::eyre!("encoding request: {e}"))?;

    send_message(&mut stream, &encoded)
        .map_err(|e| color_eyre::eyre::eyre!("sending request: {e}"))?;

    let response_data = recv_message(&mut stream)
        .map_err(|e| color_eyre::eyre::eyre!("receiving response: {e}"))?;

    let response: ManagementResponse = serde_json::from_slice(&response_data)
        .map_err(|e| color_eyre::eyre::eyre!("decoding response: {e}"))?;

    Ok(response)
}
