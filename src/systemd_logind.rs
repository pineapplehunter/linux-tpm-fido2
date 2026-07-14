use zbus::blocking::Connection;

use crate::session::SessionContext;

/// Try to detect the current session by querying systemd-logind.
///
/// Returns `Some(SessionContext)` on success, `None` if logind is
/// unavailable (no D-Bus, no session, etc.).
pub fn detect_session() -> Option<SessionContext> {
    let connection = Connection::system().ok()?;
    let pid = std::process::id();

    let session_path: String = connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "GetSessionByPID",
            &(pid,),
        )
        .ok()?
        .body()
        .deserialize()
        .ok()?;

    if session_path.is_empty() {
        return None;
    }

    let props = |name: &str| -> Option<String> {
        let raw: String = connection
            .call_method(
                Some("org.freedesktop.login1"),
                session_path.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.login1.Session", name),
            )
            .ok()?
            .body()
            .deserialize()
            .ok()?;
        // The raw value is the D-Bus variant's string representation,
        // e.g. for a string property it looks like "some-string",
        // for a struct like "(uint32 1000, ...)".
        if raw.is_empty() || raw == "/" {
            return None;
        }
        Some(raw)
    };

    let session_id = props("Id")?;

    let user_str = props("User").unwrap_or_default();
    let seat_str = props("Seat").unwrap_or_default();
    let display = props("Display").unwrap_or_default();

    let (uid, user_name) = parse_user_value(&user_str).unwrap_or((None, None));
    let seat_id = parse_seat_value(&seat_str);
    let display_str = if display.is_empty() {
        None
    } else {
        Some(display)
    };

    Some(SessionContext {
        model: crate::session::DaemonSessionModel::ActiveGraphicalSession,
        user: user_name,
        uid,
        session_id: Some(session_id),
        seat: seat_id,
        display: display_str,
        wayland_display: None,
        dbus_session_bus_address: None,
    })
}

/// Parse the "User" property of a logind session.
///
/// The User property is of type `(uo)` - a struct with a uint32 UID
/// and an object path for the user object.  The simple string
/// representation from OwnedValue::try_to_string() looks like
/// `(uint32 1000, '/org/freedesktop/login1/user/_1000')`.
fn parse_user_value(value: &str) -> Option<(Option<u32>, Option<String>)> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    let without_parens = trimmed.strip_prefix('(')?;
    let inner = without_parens.strip_suffix(')')?;
    let parts: Vec<&str> = inner.splitn(2, ',').collect();
    if parts.len() != 2 {
        return None;
    }
    let uid_str = parts[0].trim().strip_prefix("uint32 ")?;
    let uid: u32 = uid_str.parse().ok()?;
    Some((Some(uid), None))
}

/// Parse the "Seat" property of a logind session.
///
/// The Seat property is of type `(so)` - a struct with a string seat
/// ID and an object path.
fn parse_seat_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return None;
    }
    let without_parens = trimmed.strip_prefix('(')?;
    let inner = without_parens.strip_suffix(')')?;
    let seat = inner.trim().trim_matches('\'').to_owned();
    if seat.is_empty() {
        return None;
    }
    Some(seat)
}
