# Agent Notes

## Repository State

- This repo is starting a Linux TPM-backed FIDO2/WebAuthn passkey daemon; `README.md` is the current product sketch.
- A Rust crate now exists. The current implementation is not fully compatible with the fido2 spec, but works on webauthn.io.
- TPM signing, credential registration/assertion, persistent credential storage, and recovery-slot generation are implemented.
- GUI is not planned.
- CTAP2 credential storage records a `user_id` and the daemon prefers `SUDO_UID` when running under sudo so credentials can be scoped to the connected user.
- CTAP2 request handling accepts `credProps` and `residentKey` browser request shapes.
- CTAP2 makeCredential also accepts the attestation conveyance preference shape.
- Approval prompts now include peer process PID, UID, and GID in addition to session identity.
- Use the agents directory for temporary files for keeping track of tasks. Only put small texts in the directory.

## Project Direction

- The daemon should expose a browser-usable FIDO2 authenticator, by presenting a Linux virtual HID/UHID device rather than a browser extension.
- TPM 2.0 is the Root-of-Trust: support PCR-bound credentials first for secure boot state (1 and 7), then configurable PCR selections.
- Secure-boot PCR binding is wired into the current credential create/assert flow; configurable PCR selections still need follow-up work.
- Recovery uses passphrase-unlocked material that remains TPM-bound but is not PCR-bound.
- The daemon model is a single system daemon that records active session identity at startup and uses it to scope approval prompts.
- Polkit integration is the primary method for approval and stdio as fallback.
- Credential storage now uses normalized metadata, keyslot, and token tables as a LUKS2-style step toward structured unlock mechanisms and separated secrets.

## Nix Workflow

- See flake.nix for packages provided in the devShell.
- Use `nix develop --quiet -c` as a prefix when running commands.
- Format the repo with `nix fmt`; treefmt-nix wires up `nixfmt`, `rustfmt`, and `taplo` through the flake.
- Validate flake changes with `nix flake check`.

## Rust Workflow

- After modification, run `fmt`, `check`, and `test`.
- Use `cargo run -- --dry-run` to exercise the binary without opening `/dev/uhid` or `/dev/tpmrm0`.
- Runtime logging uses `log` plus `env_logger`; default level is `info`, and `RUST_LOG=debug` enables detailed UHID diagnostics.
- Real daemon runs default to `/dev/uhid` and `/dev/tpmrm0`; expect `sudo` or udev permissions while the privilege model is being designed.
- Firefox on Linux is the first browser target.
- When using sqlx, prefer to use the "query!" macro for readability instead of query function.
- Never overwrite an existing migration SQL file. Only add new migration files.
