# Agent Notes

## Repository State

- This repo is starting a Linux TPM-backed FIDO2/WebAuthn passkey daemon; `README.md` is the current product sketch.
- A Rust crate now exists. The current implementation is an early skeleton for UHID, CTAPHID, minimal CTAP2 `getInfo`, TPM placeholders, and project-local dev storage.
- TPM signing, credential registration/assertion, persistent credential storage, and recovery-slot generation are implemented; GUI is not fully implemented yet.
- Never overwrite an existing migration SQL file. Only add new migration files.
- CTAP2 credential storage records a `user_id` and the daemon prefers `SUDO_UID` when running under sudo so credentials can be scoped to the connected user.

## Project Direction

- The daemon should expose a browser-usable FIDO2 authenticator, likely by presenting a Linux virtual HID/UHID device rather than a browser extension.
- TPM 2.0 is the credential root: support PCR-bound credentials first for secure boot state, then configurable PCR selections.
- Secure-boot PCR binding is wired into the current credential create/assert flow; configurable PCR selections still need follow-up work.
- Recovery uses passphrase-unlocked material that remains TPM-bound but is not PCR-bound; the current path is env-controlled until GTK settings exist.
- The daemon model is a single system daemon that records active session identity at startup and uses it to scope approval prompts.
- Planned UI is GTK/libadwaita: a standalone approval/settings control surface exists, persists TOML preferences in the store directory, and now serves the approval IPC path that blocks the daemon until the user accepts or rejects.
- The GTK control socket checks peer credentials and rejects clients that are neither root nor the local UI user.
- Credential storage now uses normalized metadata, keyslot, and token tables as a LUKS2-style step toward structured unlock mechanisms and separated secrets.

## Nix Workflow

- Enter the dev environment with `nix develop` or let direnv load it via `.envrc` (`use flake`).
- The default dev shell provides `pkg-config`, `rustPlatform.bindgenHook`, stable Rust from `oxalica/rust-overlay`, `rust-src`, and `rust-analyzer`.
- Format the repo with `nix fmt`; treefmt-nix wires up `nixfmt`, `rustfmt`, and `taplo` through the flake.
- Validate flake changes with `nix flake check` when possible; currently the flake defines a dev shell and formatter, not packages or checks.

## Rust Workflow

- Use `nix develop -c cargo fmt`, `nix develop -c cargo check`, and `nix develop -c cargo test`.
- Use `nix develop -c cargo run -- --dry-run` to exercise the binary without opening `/dev/uhid` or `/dev/tpmrm0`.
- Runtime logging uses `log` plus `env_logger`; default level is `info`, and `RUST_LOG=debug` enables detailed UHID diagnostics.
- Real daemon runs default to `/dev/uhid` and `/dev/tpmrm0`; expect `sudo` or udev permissions while the privilege model is being designed.
- Firefox on Linux is the first browser target.

## Git-Ignored Outputs

- `.direnv/`, `result*`, `/target`, and `/.linux-tpm-fido2-store` are intentionally ignored; do not commit generated Nix links, direnv state, Rust build output, or development credentials.
