use std::{env, path::PathBuf, thread, time::Duration};

use clap::Parser;
use color_eyre::{Result, eyre::WrapErr};
use linux_tpm_fido2::{ctap2, ctaphid, hid, session, store, tpm};
use uhid_virt::{OutputEvent, StreamError, UHIDDevice};

fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::parse();

    let store_dir = absolute_path(&config.store_dir);

    if config.list_credentials {
        for credential in store::load_ctap2_credentials_from_dir(&store_dir, None)? {
            println!(
                "{}\t{}\t{}",
                hex::encode(credential.id),
                credential.rp_id,
                credential.user_name.as_deref().unwrap_or("")
            );
        }
        return Ok(());
    }

    if let Some(credential_id_hex) = &config.update_pcr_policy {
        let credential_id = hex::decode(credential_id_hex)
            .wrap_err_with(|| format!("invalid hex credential ID: {credential_id_hex}"))?;
        let recovery_passphrase =
            env::var("LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE").map_err(|_| {
                color_eyre::eyre::eyre!("LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE must be set")
            })?;
        return ctap2::update_pcr_policy_for_credential(
            &store_dir,
            Some(&config.tpm_path),
            &credential_id,
            &recovery_passphrase,
        );
    }

    if let Some(credential_id_hex) = &config.change_recovery_passphrase {
        let credential_id = hex::decode(credential_id_hex)
            .wrap_err_with(|| format!("invalid hex credential ID: {credential_id_hex}"))?;
        let old_passphrase = env::var("LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE").map_err(|_| {
            color_eyre::eyre::eyre!("LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE must be set")
        })?;
        let new_passphrase = env::var("LINUX_TPM_FIDO2_NEW_RECOVERY_PASSPHRASE").map_err(|_| {
            color_eyre::eyre::eyre!("LINUX_TPM_FIDO2_NEW_RECOVERY_PASSPHRASE must be set")
        })?;
        return ctap2::change_recovery_passphrase(
            &store_dir,
            Some(&config.tpm_path),
            &credential_id,
            &old_passphrase,
            &new_passphrase,
        );
    }

    log::info!("linux-tpm-fido2 starting");
    log::info!("uhid path: {}", config.uhid_path.display());
    log::info!("tpm path: {}", config.tpm_path.display());
    log::info!("dev store: {}", store_dir.display());
    log::info!(
        "credential database: {}",
        store::credentials_database_path_in_dir(&store_dir).display()
    );
    let session = session::SessionContext::detect();
    log::info!("session model: {}", session.describe());

    #[cfg(feature = "auto-approve")]
    if env::var("LINUX_TPM_FIDO2_AUTO_APPROVE").is_ok() {
        log::warn!("═══════════════════════════════════════════════════════");
        log::warn!("  LINUX_TPM_FIDO2_AUTO_APPROVE is SET — all approval");
        log::warn!("  prompts will be silently accepted.  DO NOT use this");
        log::warn!("  in production or with real credentials.");
        log::warn!("═══════════════════════════════════════════════════════");
    }

    if config.dry_run {
        log::info!("dry run: not opening UHID or TPM devices");
        return Ok(());
    }

    if let Err(error) = tpm::check_device(&config.tpm_path) {
        log::warn!(
            "warning: TPM device {} is not accessible yet: {error}",
            config.tpm_path.display()
        );
    } else {
        log::info!("TPM device is accessible");
    }

    let mut device = UHIDDevice::create_with_path(hid::create_params(), &config.uhid_path)
        .wrap_err_with(|| format!("opening UHID device {}", config.uhid_path.display()))?;
    log::info!("created virtual FIDO HID device; waiting for host reports");
    let mut ctaphid = ctaphid::PacketHandler::new(store_dir, Some(config.tpm_path.clone()));

    loop {
        match device.read() {
            Ok(OutputEvent::Output { data }) => {
                let Some((report, has_report_id_prefix)) = normalize_host_report(&data) else {
                    log::warn!("host -> authenticator: invalid-size len={}", data.len());
                    continue;
                };

                log::info!(
                    "host -> authenticator: {}{}",
                    ctaphid::describe_report(report),
                    if has_report_id_prefix {
                        " report_id=0"
                    } else {
                        ""
                    }
                );
                if let Some(outcome) = ctaphid.handle_packet(report) {
                    let ctaphid::PacketOutcome::Response(response) = outcome else {
                        log::debug!("waiting for continuation packet");
                        continue;
                    };
                    log::info!(
                        "authenticator -> host: cid={:#010x} cmd={} payload_len={}",
                        response.cid,
                        ctaphid::command_name(response.command),
                        response.payload.len()
                    );
                    for packet in response.packets() {
                        let written = device
                            .write(&packet)
                            .wrap_err("writing UHID input report")?;
                        log::debug!("wrote UHID input report len={written}");
                    }
                }
            }
            Ok(OutputEvent::Start { .. }) => log::info!("uhid start"),
            Ok(OutputEvent::Stop) => log::info!("uhid stop"),
            Ok(OutputEvent::Open) => log::info!("uhid open"),
            Ok(OutputEvent::Close) => log::info!("uhid close"),
            Ok(OutputEvent::GetReport {
                id,
                report_number,
                report_type,
            }) => {
                log::debug!(
                    "uhid get_report id={id} report_number={report_number} report_type={report_type:?}"
                );
                device
                    .write_get_report_reply(id, 0, Vec::new())
                    .wrap_err("writing UHID get_report reply")?;
            }
            Ok(OutputEvent::SetReport {
                id,
                report_number,
                report_type,
                data,
            }) => {
                log::debug!(
                    "uhid set_report id={id} report_number={report_number} report_type={report_type:?} len={}",
                    data.len()
                );
                device
                    .write_set_report_reply(id, 0)
                    .wrap_err("writing UHID set_report reply")?;
            }
            Err(StreamError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(StreamError::Io(error)) => return Err(error).wrap_err("reading UHID event"),
            Err(StreamError::UnknownEventType(event_type)) => {
                log::warn!("unknown UHID event type: {event_type}");
            }
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Linux TPM-backed FIDO2/WebAuthn authenticator daemon"
)]
struct Config {
    /// Do not open UHID or TPM devices; only print resolved configuration.
    #[arg(long)]
    dry_run: bool,

    /// Path to the Linux UHID character device.
    #[arg(long, default_value = "/dev/uhid")]
    uhid_path: PathBuf,

    /// Path to the TPM resource-manager device.
    #[arg(long, default_value = "/dev/tpmrm0")]
    tpm_path: PathBuf,

    /// Directory for development TPM-backed credentials.
    #[arg(long, default_value = store::DEV_STORE_DIR)]
    store_dir: PathBuf,

    /// List credential IDs, relying-party IDs, and user names, then exit.
    #[arg(long)]
    list_credentials: bool,

    /// Update PCR policy for a credential (hex ID) using recovery passphrase
    /// from LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE, then exit.
    #[arg(long)]
    update_pcr_policy: Option<String>,

    /// Change recovery passphrase for a credential (hex ID).
    /// Old passphrase from LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE,
    /// new passphrase from LINUX_TPM_FIDO2_NEW_RECOVERY_PASSPHRASE, then exit.
    #[arg(long)]
    change_recovery_passphrase: Option<String>,
}

fn absolute_path(path: &PathBuf) -> PathBuf {
    if path.is_absolute() {
        path.clone()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn normalize_host_report(data: &[u8]) -> Option<(&[u8], bool)> {
    if data.len() == hid::REPORT_SIZE {
        Some((data, false))
    } else if data.len() == hid::REPORT_SIZE + 1 && data[0] == 0 {
        Some((&data[1..], true))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_plain_report() {
        let data = [0u8; hid::REPORT_SIZE];
        let (report, has_prefix) = normalize_host_report(&data).expect("report");
        assert_eq!(report.len(), hid::REPORT_SIZE);
        assert!(!has_prefix);
    }

    #[test]
    fn normalize_strips_zero_report_id() {
        let data = [0u8; hid::REPORT_SIZE + 1];
        let (report, has_prefix) = normalize_host_report(&data).expect("report");
        assert_eq!(report.len(), hid::REPORT_SIZE);
        assert!(has_prefix);
    }

    #[test]
    fn normalize_rejects_nonzero_report_id() {
        let mut data = [0u8; hid::REPORT_SIZE + 1];
        data[0] = 1;
        assert!(normalize_host_report(&data).is_none());
    }
}
