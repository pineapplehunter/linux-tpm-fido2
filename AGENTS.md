# Agent Notes

## Repository State

- This repo is starting a Linux TPM-backed FIDO2/WebAuthn passkey daemon; `README.md` is the current product sketch.
- A Rust crate now exists. The current implementation is an early skeleton for UHID, CTAPHID, minimal CTAP2 `getInfo`, TPM placeholders, and project-local dev storage.
- TPM signing, credential registration/assertion, persistent credential storage, recovery, and GUI are not implemented yet.

## Project Direction

- The daemon should expose a browser-usable FIDO2 authenticator, likely by presenting a Linux virtual HID/UHID device rather than a browser extension.
- TPM 2.0 is the credential root: support PCR-bound credentials first for secure boot state, then configurable PCR selections.
- Recovery should use passphrase-unlocked material that remains TPM-bound but is not PCR-bound.
- Planned UI is GTK: an authentication approval prompt plus a settings UI for passkey IDs and recovery passphrases.
- Credential storage should take design cues from LUKS2 metadata: structured metadata, keyslots/tokens, and separation of encrypted secrets from unlock mechanisms.

## Nix Workflow

- Enter the dev environment with `nix develop` or let direnv load it via `.envrc` (`use flake`).
- The default dev shell provides `pkg-config`, `rustPlatform.bindgenHook`, stable Rust from `oxalica/rust-overlay`, `rust-src`, and `rust-analyzer`.
- Format Nix files with `nix fmt`; `flake.nix` sets `formatter = pkgs.nixfmt-tree`.
- Validate flake changes with `nix flake check` when possible; currently the flake defines a dev shell and formatter, not packages or checks.

## Rust Workflow

- Use `nix develop -c cargo fmt`, `nix develop -c cargo check`, and `nix develop -c cargo test`.
- Use `nix develop -c cargo run -- --dry-run` to exercise the binary without opening `/dev/uhid` or `/dev/tpmrm0`.
- Runtime logging uses `log` plus `env_logger`; default level is `info`, and `RUST_LOG=debug` enables detailed UHID diagnostics.
- Real daemon runs default to `/dev/uhid` and `/dev/tpmrm0`; expect `sudo` or udev permissions while the privilege model is being designed.
- Firefox on Linux is the first browser target.

## Git-Ignored Outputs

- `.direnv/`, `result*`, `/target`, and `/.linux-tpm-fido2-store` are intentionally ignored; do not commit generated Nix links, direnv state, Rust build output, or development credentials.
