use std::{
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    thread,
};

use color_eyre::{Result, eyre::WrapErr};
use serde::{Deserialize, Serialize};

use crate::{gtk_ui::UiSettings, session::SessionContext};

pub const CONTROL_SOCKET_FILE: &str = "control.sock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPrompt {
    pub session: SessionContext,
    pub prompt: String,
}

#[derive(Debug, Default)]
struct ApprovalPromptStateInner {
    pending_prompt: Option<ApprovalPrompt>,
    decision: Option<bool>,
}

#[derive(Debug, Default)]
pub struct ApprovalPromptState {
    inner: Mutex<ApprovalPromptStateInner>,
    condvar: Condvar,
}

impl ApprovalPromptState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_pending(&self, prompt: ApprovalPrompt) {
        let mut inner = self.inner.lock().expect("approval state lock");
        inner.pending_prompt = Some(prompt);
        inner.decision = None;
        self.condvar.notify_all();
    }

    pub fn snapshot(&self) -> Option<ApprovalPrompt> {
        self.inner
            .lock()
            .expect("approval state lock")
            .pending_prompt
            .clone()
    }

    pub fn respond(&self, decision: bool) {
        let mut inner = self.inner.lock().expect("approval state lock");
        if inner.pending_prompt.is_some() {
            inner.decision = Some(decision);
            self.condvar.notify_all();
        }
    }

    pub fn wait_for_decision(&self) -> bool {
        let mut inner = self.inner.lock().expect("approval state lock");
        while inner.decision.is_none() {
            inner = self.condvar.wait(inner).expect("approval state wait");
        }

        let decision = inner.decision.take().expect("approval decision present");
        inner.pending_prompt = None;
        decision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcRequest {
    GetUiSettings,
    SaveUiSettings(UiSettings),
    PromptApproval(ApprovalPrompt),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcResponse {
    UiSettings(UiSettings),
    Ack,
    ApprovalDecision(bool),
    Error(String),
}

pub fn control_socket_path_in_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join(CONTROL_SOCKET_FILE)
}

pub fn start_control_socket_server(
    dir: impl AsRef<Path>,
    settings: Arc<Mutex<UiSettings>>,
    approval_state: Option<Arc<ApprovalPromptState>>,
) -> Result<PathBuf> {
    let socket_path = control_socket_path_in_dir(dir.as_ref());
    if socket_path.exists() {
        fs::remove_file(&socket_path)
            .wrap_err_with(|| format!("removing stale IPC socket {}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(&socket_path)
        .wrap_err_with(|| format!("binding IPC socket {}", socket_path.display()))?;
    let thread_socket = socket_path.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(error) =
                        handle_connection(stream, &settings, approval_state.as_ref())
                    {
                        log::warn!(
                            "IPC connection on {} failed: {error:?}",
                            thread_socket.display()
                        );
                    }
                }
                Err(error) => {
                    log::warn!(
                        "IPC listener on {} failed: {error:?}",
                        thread_socket.display()
                    );
                    break;
                }
            }
        }
    });

    Ok(socket_path)
}

pub fn send_request(socket_path: impl AsRef<Path>, request: &IpcRequest) -> Result<IpcResponse> {
    let stream = UnixStream::connect(socket_path.as_ref()).wrap_err_with(|| {
        format!(
            "connecting to IPC socket {}",
            socket_path.as_ref().display()
        )
    })?;

    let mut writer = BufWriter::new(stream.try_clone().wrap_err("cloning IPC stream")?);
    serde_json::to_writer(&mut writer, request).wrap_err("serializing IPC request")?;
    writer
        .write_all(b"\n")
        .wrap_err("terminating IPC request line")?;
    writer.flush().wrap_err("flushing IPC request")?;
    drop(writer);

    let mut reader = BufReader::new(stream);
    let mut response_json = String::new();
    reader
        .read_line(&mut response_json)
        .wrap_err("reading IPC response")?;
    serde_json::from_str(response_json.trim_end()).wrap_err("deserializing IPC response")
}

fn handle_connection(
    stream: UnixStream,
    settings: &Arc<Mutex<UiSettings>>,
    approval_state: Option<&Arc<ApprovalPromptState>>,
) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone().wrap_err("cloning IPC reader stream")?);
    let mut request_json = String::new();
    reader
        .read_line(&mut request_json)
        .wrap_err("reading IPC request")?;
    let request: IpcRequest =
        serde_json::from_str(request_json.trim_end()).wrap_err("deserializing IPC request")?;

    let response = match request {
        IpcRequest::GetUiSettings => {
            IpcResponse::UiSettings(settings.lock().expect("settings lock").clone())
        }
        IpcRequest::SaveUiSettings(updated) => {
            *settings.lock().expect("settings lock") = updated;
            IpcResponse::Ack
        }
        IpcRequest::PromptApproval(prompt) => {
            log::info!(
                "IPC approval prompt for session {}: {}",
                prompt.session.describe(),
                prompt.prompt
            );
            if let Some(state) = approval_state {
                state.set_pending(prompt);
                IpcResponse::ApprovalDecision(state.wait_for_decision())
            } else {
                IpcResponse::ApprovalDecision(true)
            }
        }
    };

    let mut writer = BufWriter::new(stream);
    serde_json::to_writer(&mut writer, &response).wrap_err("serializing IPC response")?;
    writer
        .write_all(b"\n")
        .wrap_err("terminating IPC response line")?;
    writer.flush().wrap_err("flushing IPC response")
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalPrompt, CONTROL_SOCKET_FILE, IpcRequest, IpcResponse, control_socket_path_in_dir,
        start_control_socket_server,
    };
    use crate::{
        gtk_ui::UiSettings,
        session::{DaemonSessionModel, SessionContext},
    };
    use std::{
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn control_socket_path_is_in_store_dir() {
        let path = control_socket_path_in_dir("/tmp/example-store");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(CONTROL_SOCKET_FILE)
        );
    }

    #[test]
    fn ipc_server_round_trips_settings_and_prompt() {
        let dir = std::env::temp_dir().join(format!(
            "linux-tpm-fido2-ipc-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let settings = Arc::new(Mutex::new(UiSettings::default()));
        let socket_path =
            start_control_socket_server(&dir, settings.clone(), None).expect("start server");

        let response =
            super::send_request(&socket_path, &IpcRequest::GetUiSettings).expect("get settings");
        assert_eq!(response, IpcResponse::UiSettings(UiSettings::default()));

        let updated = UiSettings {
            pinned_relying_parties: vec!["example.com".to_owned()],
            recovery_label: "backup".to_owned(),
        };
        let response =
            super::send_request(&socket_path, &IpcRequest::SaveUiSettings(updated.clone()))
                .expect("save settings");
        assert_eq!(response, IpcResponse::Ack);
        assert_eq!(*settings.lock().expect("settings lock"), updated);

        let prompt = ApprovalPrompt {
            session: SessionContext {
                model: DaemonSessionModel::ActiveGraphicalSession,
                user: Some("alice".to_owned()),
                uid: Some(1000),
                session_id: Some("c2".to_owned()),
                seat: Some("seat0".to_owned()),
                display: Some(":0".to_owned()),
                wayland_display: None,
                dbus_session_bus_address: None,
            },
            prompt: "Approve passkey request".to_owned(),
        };
        let response = super::send_request(&socket_path, &IpcRequest::PromptApproval(prompt))
            .expect("prompt approval");
        assert_eq!(response, IpcResponse::ApprovalDecision(true));
    }
}
