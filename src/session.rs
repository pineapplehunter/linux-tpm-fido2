use std::env;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DaemonSessionModel {
    #[default]
    ActiveGraphicalSession,
    PerUserDaemon,
    SystemBroker,
}

impl DaemonSessionModel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActiveGraphicalSession => "active-graphical-session",
            Self::PerUserDaemon => "per-user-daemon",
            Self::SystemBroker => "system-broker",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    pub model: DaemonSessionModel,
    pub user: Option<String>,
    pub uid: Option<u32>,
    pub session_id: Option<String>,
    pub seat: Option<String>,
    pub display: Option<String>,
    pub wayland_display: Option<String>,
    pub dbus_session_bus_address: Option<String>,
}

impl SessionContext {
    pub fn detect() -> Self {
        // Prefer dynamic detection via systemd-logind
        if let Some(ctx) = crate::systemd_logind::detect_session() {
            return ctx;
        }

        // Fall back to environment variables
        let uid = env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| env::var("UID").ok().and_then(|value| value.parse().ok()))
            .or_else(|| Some(unsafe { libc::geteuid() }));

        Self {
            model: DaemonSessionModel::default(),
            user: env::var("SUDO_USER")
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| env::var("USER").ok().filter(|value| !value.is_empty())),
            uid,
            session_id: env::var("XDG_SESSION_ID")
                .ok()
                .filter(|value| !value.is_empty()),
            seat: env::var("XDG_SEAT").ok().filter(|value| !value.is_empty()),
            display: env::var("DISPLAY").ok().filter(|value| !value.is_empty()),
            wayland_display: env::var("WAYLAND_DISPLAY")
                .ok()
                .filter(|value| !value.is_empty()),
            dbus_session_bus_address: env::var("DBUS_SESSION_BUS_ADDRESS")
                .ok()
                .filter(|value| !value.is_empty()),
        }
    }

    pub fn describe(&self) -> String {
        let mut parts = vec![format!("model={}", self.model.as_str())];
        if let Some(user) = &self.user {
            parts.push(format!("user={user}"));
        }
        if let Some(uid) = self.uid {
            parts.push(format!("uid={uid}"));
        }
        if let Some(session_id) = &self.session_id {
            parts.push(format!("session={session_id}"));
        }
        if let Some(seat) = &self.seat {
            parts.push(format!("seat={seat}"));
        }
        if let Some(display) = &self.display {
            parts.push(format!("display={display}"));
        }
        if let Some(wayland_display) = &self.wayland_display {
            parts.push(format!("wayland={wayland_display}"));
        }
        if self.dbus_session_bus_address.is_some() {
            parts.push("dbus=session-bus".to_owned());
        }
        parts.join(" ")
    }
}

impl SessionContext {
    /// Verify that the current session still matches this context.
    ///
    /// Re-queries systemd-logind (or env vars as fallback) and
    /// compares the uid and session_id.  Returns `true` when the
    /// caller's session has not changed.
    pub fn verify_matches_current(&self) -> bool {
        let current = Self::detect();
        if current.uid != self.uid {
            log::warn!(
                "session UID changed: expected {:?}, got {:?}",
                self.uid,
                current.uid
            );
            return false;
        }
        if current.session_id != self.session_id {
            log::warn!(
                "session ID changed: expected {:?}, got {:?}",
                self.session_id,
                current.session_id
            );
            return false;
        }
        true
    }
}

impl Default for SessionContext {
    fn default() -> Self {
        Self::detect()
    }
}

#[cfg(test)]
mod tests {
    use super::{DaemonSessionModel, SessionContext};

    #[test]
    fn describe_includes_detected_session_identity() {
        let session = SessionContext {
            model: DaemonSessionModel::ActiveGraphicalSession,
            user: Some("alice".to_owned()),
            uid: Some(1000),
            session_id: Some("c2".to_owned()),
            seat: Some("seat0".to_owned()),
            display: Some(":0".to_owned()),
            wayland_display: Some("wayland-0".to_owned()),
            dbus_session_bus_address: Some("unix:path=/run/user/1000/bus".to_owned()),
        };

        assert_eq!(
            session.describe(),
            "model=active-graphical-session user=alice uid=1000 session=c2 seat=seat0 display=:0 wayland=wayland-0 dbus=session-bus"
        );
    }
}
