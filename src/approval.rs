use std::{
    io::{self, Write},
    path::Path,
};

use crate::{
    ipc::{self, ApprovalPrompt, IpcRequest, IpcResponse},
    session,
};

pub fn approve(prompt: &str, session: &session::SessionContext, store_dir: &Path) -> bool {
    if std::env::var("LINUX_TPM_FIDO2_AUTO_APPROVE").is_ok() {
        log::info!("auto-approving: {prompt}");
        return true;
    }

    if let Some(approved) = approve_via_ipc(prompt, session, store_dir) {
        return approved;
    }

    let mut stdout = io::stdout();
    if write!(
        stdout,
        "[{session}] {prompt}? [y/N] ",
        session = session.describe()
    )
    .and_then(|_| stdout.flush())
    .is_err()
    {
        return false;
    }

    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }

    matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes")
}

fn approve_via_ipc(
    prompt: &str,
    session: &session::SessionContext,
    store_dir: &Path,
) -> Option<bool> {
    let socket_path = ipc::control_socket_path_in_dir(store_dir);
    if !socket_path.exists() {
        return None;
    }

    let request = IpcRequest::PromptApproval(ApprovalPrompt {
        session: session.clone(),
        prompt: prompt.to_owned(),
        peer: None,
    });

    match ipc::send_request(&socket_path, &request) {
        Ok(IpcResponse::ApprovalDecision(decision)) => {
            log::info!(
                "approval handled by GTK IPC at {} with decision={decision}",
                socket_path.display()
            );
            Some(decision)
        }
        Ok(other) => {
            log::warn!(
                "GTK IPC approval returned unexpected response at {}: {other:?}",
                socket_path.display()
            );
            None
        }
        Err(error) => {
            log::warn!(
                "GTK IPC approval unavailable at {}: {error:?}",
                socket_path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::approve;
    use crate::{
        ipc,
        ipc::UiSettings,
        session::{DaemonSessionModel, SessionContext},
    };
    use std::{
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn approve_uses_ipc_when_socket_exists() {
        let dir = std::env::temp_dir().join(format!(
            "linux-tpm-fido2-approval-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let settings = Arc::new(Mutex::new(UiSettings::default()));
        let server_uid = SessionContext::detect().uid;
        let _socket_path = ipc::start_control_socket_server(&dir, settings, server_uid, None)
            .expect("start ipc server");

        let session = SessionContext {
            model: DaemonSessionModel::ActiveGraphicalSession,
            user: Some("alice".to_owned()),
            uid: Some(1000),
            session_id: Some("c2".to_owned()),
            seat: Some("seat0".to_owned()),
            display: Some(":0".to_owned()),
            wayland_display: None,
            dbus_session_bus_address: None,
        };

        assert!(approve("Approve passkey request", &session, &dir));
    }
}
