use std::io::{self, Write};

use crate::session;

pub fn approve(prompt: &str, session: &session::SessionContext) -> bool {
    #[cfg(any(feature = "auto-approve", test))]
    if std::env::var("LINUX_TPM_FIDO2_AUTO_APPROVE").is_ok() {
        log::warn!("auto-approving (LINUX_TPM_FIDO2_AUTO_APPROVE): {prompt}");
        return true;
    }

    // Prefer polkit when a session ID is available
    if let Some(session_id) = &session.session_id {
        match crate::polkit::check_session(session_id) {
            Ok(true) => {
                log::info!("polkit authorized approval: {prompt}");
                return true;
            }
            Ok(false) => {
                log::warn!("polkit denied approval: {prompt}");
                return false;
            }
            Err(error) => {
                log::warn!("polkit unavailable, falling back: {error:?}");
            }
        }
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

#[cfg(test)]
mod tests {
    use super::approve;
    use crate::session::{DaemonSessionModel, SessionContext};

    #[test]
    fn auto_approve_returns_true() {
        let session = SessionContext {
            model: DaemonSessionModel::ActiveGraphicalSession,
            user: Some("alice".to_owned()),
            uid: Some(1000),
            session_id: None,
            seat: Some("seat0".to_owned()),
            display: Some(":0".to_owned()),
            wayland_display: None,
            dbus_session_bus_address: None,
        };
        // SAFETY: tests are single-threaded
        unsafe { std::env::set_var("LINUX_TPM_FIDO2_AUTO_APPROVE", "1") };
        assert!(approve("Approve passkey request", &session));
        unsafe { std::env::remove_var("LINUX_TPM_FIDO2_AUTO_APPROVE") };
    }
}
