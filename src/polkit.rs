use std::collections::HashMap;

use color_eyre::Result;
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedValue, Value};

const POLKIT_AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const POLKIT_AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const POLKIT_ACTION_ID: &str = "io.github.pineapplehunter.linux-tpm-fido2.approve";

/// Check with polkit whether the caller is authorized.
///
/// Uses a `unix-process` subject with the given PID and its
/// start time (in microseconds since the UNIX epoch).
///
/// Returns `Ok(true)` when authorized, `Ok(false)` when denied,
/// and `Err` when polkit is unavailable or communication fails.
pub fn check_process(pid: u32) -> Result<bool> {
    let start_time = process_start_time_us(pid)?;

    let conn = Connection::system()?;

    let mut subject_details: HashMap<&str, Value> = HashMap::new();
    subject_details.insert("pid", Value::from(pid));
    subject_details.insert("start-time", Value::from(start_time));
    subject_details.insert("uid", Value::from(unsafe { libc::getuid() }));
    let subject = ("unix-process", subject_details);

    let empty_details: HashMap<&str, &str> = HashMap::new();
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
                empty_details,
                flags,
                cancellation_id,
            ),
        )?
        .body()
        .deserialize()?;

    Ok(result.0)
}

/// Read the process start time in microseconds since the UNIX epoch
/// from `/proc/<pid>/stat`.
fn process_start_time_us(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // Fields are space-separated; field 22 (1-indexed) is starttime
    // in clock ticks since boot.  After the comm field (which may
    // contain spaces/parens) we skip to the fields after the closing ')'.
    let after_comm = stat
        .rfind(')')
        .ok_or_else(|| color_eyre::eyre::eyre!("malformed /proc/{pid}/stat"))?;
    let fields: Vec<&str> = stat[after_comm + 2..].split_whitespace().collect();
    // fields[0] is state (field 3), fields[19] is starttime (field 22)
    let ticks: u64 = fields
        .get(19)
        .ok_or_else(|| color_eyre::eyre::eyre!("missing starttime in /proc/{pid}/stat"))?
        .parse()?;
    // sysconf(_SC_CLK_TCK) is typically 100 on Linux
    let ticks_per_sec: u64 = 100;
    Ok(ticks * 1_000_000 / ticks_per_sec)
}
