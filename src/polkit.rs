use std::collections::HashMap;

use color_eyre::Result;
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedValue, Value};

const POLKIT_AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const POLKIT_AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const POLKIT_ACTION_ID: &str = "org.linux_tpm_fido2.approve";

/// Check with polkit whether the session is authorized.
///
/// Returns `Ok(true)` when authorized, `Ok(false)` when denied,
/// and `Err` when polkit is unavailable or communication fails.
pub fn check_session(session_id: &str) -> Result<bool> {
    let conn = Connection::system()?;

    let subject = build_unix_session_subject(session_id);
    let flags = 0u32;
    let cancellation_id = String::new();

    let result: (bool, HashMap<String, OwnedValue>, bool) = conn
        .call_method(
            Some(POLKIT_AUTHORITY),
            POLKIT_AUTHORITY_PATH,
            Some(POLKIT_AUTHORITY_IFACE),
            "CheckAuthorization",
            &(
                subject,
                POLKIT_ACTION_ID,
                HashMap::<String, Value>::new(),
                flags,
                cancellation_id,
            ),
        )?
        .body()
        .deserialize()?;

    Ok(result.0)
}

/// Build an `a(sa{sv})` subject identifying the session via
/// "unix-session" kind with session-id detail.
fn build_unix_session_subject<'a>(
    session_id: &'a str,
) -> Vec<(&'a str, HashMap<&'a str, Value<'a>>)> {
    let mut details: HashMap<&str, Value> = HashMap::new();
    details.insert("session-id", Value::from(session_id));
    vec![("unix-session", details)]
}
