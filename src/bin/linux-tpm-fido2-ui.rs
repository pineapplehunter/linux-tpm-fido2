use std::path::PathBuf;

use clap::Parser;
use color_eyre::{Result, eyre::WrapErr};

use linux_tpm_fido2::gtk_ui::{self, GtkUiConfig};

fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::parse();
    log::info!("starting GTK control surface");
    log::info!("store dir: {}", config.store_dir.display());

    gtk_ui::launch(GtkUiConfig {
        store_dir: config.store_dir,
    })
    .wrap_err("running GTK control surface")
}

#[derive(Debug, Parser)]
#[command(version, about = "GTK approval and settings UI for linux-tpm-fido2")]
struct Config {
    /// Directory for development TPM-backed credentials.
    #[arg(long, default_value = linux_tpm_fido2::store::DEV_STORE_DIR)]
    store_dir: PathBuf,
}
