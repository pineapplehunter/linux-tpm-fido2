use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use color_eyre::{Result, eyre::WrapErr};
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, Button, Entry, Label, ListBox, ListBoxRow,
    Notebook, Orientation, ScrolledWindow, prelude::*,
};
use serde::{Deserialize, Serialize};

use crate::{ipc, session, store};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSummary {
    pub rp_id: String,
    pub user_label: String,
    pub sign_count: u32,
    pub recovery_label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GtkUiConfig {
    pub store_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSettings {
    pub pinned_relying_parties: Vec<String>,
    pub recovery_label: String,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            pinned_relying_parties: Vec::new(),
            recovery_label: "recovery slot".to_owned(),
        }
    }
}

impl Default for GtkUiConfig {
    fn default() -> Self {
        Self {
            store_dir: store::dev_store_dir(),
        }
    }
}

pub fn launch(config: GtkUiConfig) -> Result<()> {
    let credentials = load_credential_summaries(&config.store_dir)?;
    let settings = load_ui_settings_from_dir(&config.store_dir)?;
    let settings_state = Arc::new(Mutex::new(settings.clone()));
    let session = session::SessionContext::detect();
    let socket_path = ipc::start_control_socket_server(&config.store_dir, settings_state.clone())?;
    log::info!("GTK IPC socket: {}", socket_path.display());
    let app = Application::builder()
        .application_id("org.linux_tpm_fido2.control")
        .build();

    app.connect_activate(move |app| {
        build_ui(
            app,
            &session,
            &config.store_dir,
            &credentials,
            &settings,
            settings_state.clone(),
            &socket_path,
        );
    });

    let _code = app.run();
    Ok(())
}

pub fn load_credential_summaries(dir: impl AsRef<Path>) -> Result<Vec<CredentialSummary>> {
    let credentials = store::load_ctap2_credentials_from_dir(dir.as_ref())
        .wrap_err("loading credentials for GTK UI")?;

    Ok(credentials
        .into_iter()
        .map(|credential| CredentialSummary {
            rp_id: credential.rp_id,
            user_label: credential
                .user_display_name
                .or(credential.user_name)
                .unwrap_or_else(|| "unknown user".to_owned()),
            sign_count: credential.sign_count,
            recovery_label: credential
                .recovery
                .and_then(|recovery| recovery.label)
                .or_else(|| Some("recovery slot".to_owned())),
        })
        .collect())
}

pub fn ui_settings_path_in_dir(dir: impl AsRef<Path>) -> PathBuf {
    dir.as_ref().join("ui-settings.toml")
}

pub fn load_ui_settings_from_dir(dir: impl AsRef<Path>) -> Result<UiSettings> {
    let path = ui_settings_path_in_dir(dir.as_ref());
    if !path.exists() {
        return Ok(UiSettings::default());
    }

    let raw = fs::read_to_string(&path)
        .wrap_err_with(|| format!("reading GTK settings from {}", path.display()))?;
    toml::from_str(&raw).wrap_err_with(|| format!("parsing GTK settings from {}", path.display()))
}

pub fn save_ui_settings_to_dir(dir: impl AsRef<Path>, settings: &UiSettings) -> Result<()> {
    let path = ui_settings_path_in_dir(dir.as_ref());
    let raw = toml::to_string_pretty(settings).wrap_err("serializing GTK settings to TOML")?;
    fs::create_dir_all(dir.as_ref())
        .wrap_err_with(|| format!("creating {}", dir.as_ref().display()))?;
    fs::write(&path, raw).wrap_err_with(|| format!("writing GTK settings to {}", path.display()))
}

fn build_ui(
    app: &Application,
    session: &session::SessionContext,
    store_dir: &Path,
    credentials: &[CredentialSummary],
    settings: &UiSettings,
    settings_state: Arc<Mutex<UiSettings>>,
    socket_path: &Path,
) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("linux-tpm-fido2")
        .default_width(760)
        .default_height(520)
        .build();

    let notebook = Notebook::new();
    notebook.set_hexpand(true);
    notebook.set_vexpand(true);

    let approval_page = build_approval_page(session);
    let approval_label = Label::new(Some("Approval"));
    notebook.append_page(&approval_page, Some(&approval_label));

    let settings_page = build_settings_page(
        store_dir,
        credentials,
        settings,
        settings_state,
        socket_path,
    );
    let settings_label = Label::new(Some("Settings"));
    notebook.append_page(&settings_page, Some(&settings_label));

    window.set_child(Some(&notebook));
    window.present();
}

fn build_approval_page(session: &session::SessionContext) -> GtkBox {
    let page = GtkBox::new(Orientation::Vertical, 12);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    let title = Label::new(Some("Approve authenticator request"));
    title.add_css_class("title-1");
    title.set_wrap(true);

    let session_label = Label::new(Some(&format!("Session: {}", session.describe())));
    session_label.set_wrap(true);

    let prompt_label = Label::new(Some(
        "This window will become the GTK approval prompt once the daemon connects it to IPC.",
    ));
    prompt_label.set_wrap(true);

    let result_label = Label::new(Some("Waiting for user action."));
    result_label.set_wrap(true);

    let buttons = GtkBox::new(Orientation::Horizontal, 12);
    let accept = Button::with_label("Accept");
    let reject = Button::with_label("Reject");

    {
        let result_label = result_label.clone();
        accept.connect_clicked(move |_| {
            result_label.set_text("Approved.");
            log::info!("GTK approval accepted for current session");
        });
    }
    {
        let result_label = result_label.clone();
        reject.connect_clicked(move |_| {
            result_label.set_text("Rejected.");
            log::info!("GTK approval rejected for current session");
        });
    }

    buttons.append(&accept);
    buttons.append(&reject);

    page.append(&title);
    page.append(&session_label);
    page.append(&prompt_label);
    page.append(&result_label);
    page.append(&buttons);
    page
}

fn build_settings_page(
    store_dir: &Path,
    credentials: &[CredentialSummary],
    settings: &UiSettings,
    settings_state: Arc<Mutex<UiSettings>>,
    socket_path: &Path,
) -> GtkBox {
    let page = GtkBox::new(Orientation::Vertical, 12);
    page.set_margin_top(24);
    page.set_margin_bottom(24);
    page.set_margin_start(24);
    page.set_margin_end(24);

    let title = Label::new(Some("Stored passkeys and recovery slots"));
    title.add_css_class("title-1");
    title.set_wrap(true);

    let store_label = Label::new(Some(&format!("Store: {}", store_dir.display())));
    store_label.set_wrap(true);

    let pinned_entry = Entry::new();
    pinned_entry.set_placeholder_text(Some("example.com, login.example.com"));
    pinned_entry.set_text(&settings.pinned_relying_parties.join(", "));

    let recovery_entry = Entry::new();
    recovery_entry.set_placeholder_text(Some("recovery slot"));
    recovery_entry.set_text(&settings.recovery_label);

    let save_status = Label::new(Some(&format!(
        "Settings file: {}",
        ui_settings_path_in_dir(store_dir).display()
    )));
    save_status.set_wrap(true);

    let ipc_status = Label::new(Some(&format!("IPC socket: {}", socket_path.display())));
    ipc_status.set_wrap(true);

    let pinned_label = Label::new(Some("Pinned passkey IDs"));
    pinned_label.add_css_class("heading");
    pinned_label.set_wrap(true);

    let recovery_label = Label::new(Some("Recovery passphrase label"));
    recovery_label.add_css_class("heading");
    recovery_label.set_wrap(true);

    let save_button = Button::with_label("Save settings");
    {
        let store_dir = store_dir.to_path_buf();
        let pinned_entry = pinned_entry.clone();
        let recovery_entry = recovery_entry.clone();
        let save_status = save_status.clone();
        let settings_state = settings_state.clone();
        save_button.connect_clicked(move |_| {
            let pinned_relying_parties = pinned_entry
                .text()
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let settings = UiSettings {
                pinned_relying_parties,
                recovery_label: recovery_entry.text().to_string(),
            };

            match save_ui_settings_to_dir(&store_dir, &settings) {
                Ok(()) => {
                    *settings_state.lock().expect("settings lock") = settings.clone();
                    save_status.set_text(&format!(
                        "Saved settings to {}",
                        ui_settings_path_in_dir(&store_dir).display()
                    ));
                    log::info!(
                        "saved GTK settings: pinned_ids={} recovery_label={}",
                        settings.pinned_relying_parties.len(),
                        settings.recovery_label
                    );
                }
                Err(error) => {
                    save_status.set_text(&format!("Failed to save settings: {error}"));
                    log::warn!("failed to save GTK settings: {error:?}");
                }
            }
        });
    }

    let pinned_hint = Label::new(Some(
        "Comma-separated relying-party IDs shown in the control surface.",
    ));
    pinned_hint.set_wrap(true);

    let recovery_hint = Label::new(Some(
        "This label will be paired with the recovery passphrase configuration.",
    ));
    recovery_hint.set_wrap(true);

    let form = GtkBox::new(Orientation::Vertical, 8);
    form.append(&pinned_label);
    form.append(&pinned_entry);
    form.append(&pinned_hint);
    form.append(&recovery_label);
    form.append(&recovery_entry);
    form.append(&recovery_hint);
    form.append(&save_button);
    form.append(&save_status);
    form.append(&ipc_status);

    let scroller = ScrolledWindow::new();
    scroller.set_hexpand(true);
    scroller.set_vexpand(true);

    let list = ListBox::new();
    for credential in credentials {
        list.append(&credential_row(credential));
    }

    if credentials.is_empty() {
        let row = ListBoxRow::new();
        row.set_child(Some(&Label::new(Some("No credentials stored yet."))));
        list.append(&row);
    }

    scroller.set_child(Some(&list));

    page.append(&title);
    page.append(&store_label);
    page.append(&form);
    page.append(&scroller);
    page
}

fn credential_row(summary: &CredentialSummary) -> ListBoxRow {
    let row = ListBoxRow::new();
    let box_ = GtkBox::new(Orientation::Vertical, 6);
    let headline = Label::new(Some(&format!("{} · {}", summary.rp_id, summary.user_label)));
    headline.add_css_class("heading");
    headline.set_wrap(true);

    let details = Label::new(Some(&format!(
        "sign_count={} recovery={}",
        summary.sign_count,
        summary.recovery_label.as_deref().unwrap_or("recovery slot")
    )));
    details.set_wrap(true);

    box_.append(&headline);
    box_.append(&details);
    row.set_child(Some(&box_));
    row
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialSummary, UiSettings, load_credential_summaries, load_ui_settings_from_dir,
        save_ui_settings_to_dir,
    };
    use crate::store::{self, StoredCtap2Credential, StoredTpmKey};

    #[test]
    fn ui_settings_round_trip_through_toml() {
        let dir = std::env::temp_dir().join(format!(
            "linux-tpm-fido2-gtk-ui-settings-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos()
        ));

        let settings = UiSettings {
            pinned_relying_parties: vec!["example.com".to_owned(), "login.example.com".to_owned()],
            recovery_label: "backup".to_owned(),
        };
        save_ui_settings_to_dir(&dir, &settings).expect("save settings");

        let loaded = load_ui_settings_from_dir(&dir).expect("load settings");
        assert_eq!(loaded, settings);
    }

    #[test]
    fn missing_store_loads_no_credential_summaries() {
        let dir = std::env::temp_dir().join(format!(
            "linux-tpm-fido2-gtk-ui-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos()
        ));

        let summaries = load_credential_summaries(&dir).expect("load summaries");
        assert!(summaries.is_empty());
    }

    #[test]
    fn credential_summaries_include_user_and_recovery_labels() {
        let dir = std::env::temp_dir().join(format!(
            "linux-tpm-fido2-gtk-ui-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after Unix epoch")
                .as_nanos()
        ));

        let credentials = vec![StoredCtap2Credential {
            id: vec![1],
            rp_id: "example.com".to_owned(),
            user_handle: vec![2],
            user_name: Some("alice".to_owned()),
            user_display_name: Some("Alice Example".to_owned()),
            key: StoredTpmKey {
                private: vec![3],
                public: vec![4],
                public_key_x: vec![5; 32],
                public_key_y: vec![6; 32],
            },
            policy: None,
            recovery: None,
            sign_count: 7,
        }];
        store::save_ctap2_credentials_to_dir(&dir, &credentials).expect("save credentials");

        let summaries = load_credential_summaries(&dir).expect("load summaries");
        assert_eq!(
            summaries,
            vec![CredentialSummary {
                rp_id: "example.com".to_owned(),
                user_label: "Alice Example".to_owned(),
                sign_count: 7,
                recovery_label: Some("recovery slot".to_owned()),
            }]
        );
    }
}
