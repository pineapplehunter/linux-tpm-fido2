# linux-tpm-fido2

`linux-tpm-fido2` is an experimental Linux daemon for providing a FIDO2/WebAuthn passkey authenticator backed by a TPM 2.0.

The goal is to let browsers use TPM-protected credentials through the normal FIDO2 authenticator path while keeping user approval and credential management local to the desktop.

## Goals

- Expose a browser-usable FIDO2 authenticator backed by TPM 2.0 keys.
- Support credentials bound to TPM PCR policy, starting with secure boot state and allowing additional PCR selections later.
- Support passphrase-based recovery for credentials using TPM-bound material that is not PCR-bound.
- Route approval prompts through the active graphical session while the daemon remains a single system service.
- Show a GTK approval prompt for authentication requests with accept/reject actions.
- Provide a GTK settings UI for stored passkey IDs and recovery passphrase configuration.
- Store credential metadata using a LUKS2-inspired design: structured metadata, keyslots, tokens, and clear separation between encrypted secrets and unlock mechanisms.

## Initial Architecture Sketch

- A system or user daemon presents a virtual FIDO2 HID authenticator to browsers.
- The daemon implements CTAP2/WebAuthn authenticator operations and delegates credential signing or unsealing to TPM 2.0.
- A local GTK agent handles user presence/user verification prompts and settings.
- Metadata stores public credential data, TPM public/private blobs, PCR policy description, recovery slots, and UI-facing labels.
- The current daemon model is a system daemon that records the active session identity at startup and uses it to scope approval prompts.

## Development

Enter the development shell with:

```sh
nix develop
```

Useful commands:

```sh
nix develop -c cargo fmt
nix develop -c cargo check
nix develop -c cargo test
nix fmt
nix develop -c cargo run -- --dry-run
```

Logging uses the `log` crate with `env_logger`; default level is `info`. Use `RUST_LOG=debug nix develop -c cargo run -- ...` for lower-level UHID diagnostics.

The daemon currently accepts `--uhid-path`, `--tpm-path`, `--store-dir`, and `--dry-run`. Defaults are `/dev/uhid`, `/dev/tpmrm0`, and `.linux-tpm-fido2-store`. A real run will usually need `sudo` or udev permissions that allow access to the UHID and TPM device nodes.

There is also a standalone GTK4 control surface in `src/bin/linux-tpm-fido2-ui.rs` that shows an approval pane and a settings pane backed by the SQLite credential store.

`nix fmt` uses treefmt-nix to run `nixfmt`, `rustfmt`, and `taplo` from the flake.

## Current Status

The daemon can create a UHID-backed FIDO HID device, handle CTAPHID `INIT`, `PING`, `CBOR`, `WINK`, and `CANCEL`, and implement CTAP2 `authenticatorGetInfo`, `authenticatorMakeCredential`, and `authenticatorGetAssertion`.

CTAP2 credentials are TPM-backed P-256 ECDSA keys persisted in a normalized SQLite store with separate metadata, keyslot, and token tables managed by `sqlx` migrations. Secure-boot PCR binding is wired for credential creation and assertion; recovery slots can now be generated during registration with `LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE`, approval prompts are scoped to the active graphical session, and the GTK control surface is in place while production metadata durability remains pending.
