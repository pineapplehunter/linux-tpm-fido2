use std::path::{Path, PathBuf};

use color_eyre::{Result, eyre::WrapErr};
use gtk4::{
    Application, ApplicationWindow, Box as GtkBox, Button, Label, ListBox, ListBoxRow, Notebook,
    Orientation, ScrolledWindow, prelude::*,
};

use crate::{session, store};

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

impl Default for GtkUiConfig {
    fn default() -> Self {
        Self {
            store_dir: store::dev_store_dir(),
        }
    }
}

pub fn launch(config: GtkUiConfig) -> Result<()> {
    let credentials = load_credential_summaries(&config.store_dir)?;
    let session = session::SessionContext::detect();
    let app = Application::builder()
        .application_id("org.linux_tpm_fido2.control")
        .build();

    app.connect_activate(move |app| {
        build_ui(app, &session, &config.store_dir, &credentials);
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

fn build_ui(
    app: &Application,
    session: &session::SessionContext,
    store_dir: &Path,
    credentials: &[CredentialSummary],
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

    let settings_page = build_settings_page(store_dir, credentials);
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

fn build_settings_page(store_dir: &Path, credentials: &[CredentialSummary]) -> GtkBox {
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
    use super::{CredentialSummary, load_credential_summaries};
    use crate::store::{self, StoredCtap2Credential, StoredTpmKey};

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
