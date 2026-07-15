use zbus::{
    blocking::Connection,
    zvariant::{OwnedObjectPath, OwnedValue},
};

use crate::session::SessionContext;

/// Try to detect the active graphical session by querying systemd-logind.
///
/// A system daemon is not itself attached to the user's session, so looking
/// up the daemon PID would identify no session or the root session. Instead,
/// select the active graphical session from logind's session list.
pub fn detect_session() -> Option<SessionContext> {
    let connection = Connection::system().ok()?;
    let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> = connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "ListSessions",
            &(),
        )
        .ok()?
        .body()
        .deserialize()
        .ok()?;

    let mut active_non_graphical = None;
    for (session_id, uid, user, seat, path) in sessions {
        let path = path.as_str();
        if seat.is_empty()
            || !bool::try_from(session_property(&connection, path, "Active")?).ok()?
        {
            continue;
        }

        let session_type = String::try_from(session_property(&connection, path, "Type")?).ok()?;
        let leader_pid = u32::try_from(session_property(&connection, path, "Leader")?).ok()?;
        let display = String::try_from(session_property(&connection, path, "Display")?)
            .ok()
            .filter(|value| !value.is_empty());
        let context = SessionContext {
            model: crate::session::DaemonSessionModel::ActiveGraphicalSession,
            user: (!user.is_empty()).then_some(user),
            uid: Some(uid),
            session_id: Some(session_id),
            leader_pid: Some(leader_pid),
            seat: Some(seat),
            display,
            wayland_display: None,
            dbus_session_bus_address: None,
        };

        if session_type == "x11" || session_type == "wayland" {
            return Some(context);
        }
        active_non_graphical.get_or_insert(context);
    }

    active_non_graphical
}

fn session_property(
    connection: &Connection,
    session_path: &str,
    property: &str,
) -> Option<OwnedValue> {
    connection
        .call_method(
            Some("org.freedesktop.login1"),
            session_path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.login1.Session", property),
        )
        .ok()?
        .body()
        .deserialize()
        .ok()
}
