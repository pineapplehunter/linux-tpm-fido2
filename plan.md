# Implementation Plan

## Generel things to keep in mind.
- Commit the changes to git after a task
- Do these tests
    - cargo check
    - cargo test
    - nixos test
    - nix fmt
- Fixup cargo clippy after a POC implementation
- When writing bash scripts for nix, generally keep the script in a separate file and use lib.readFile to import it.
- Create a todolist to accomplish each task.
- Update README and AGENTS.md when a new feature gets implemented or the implementation changed from the original docs.
- Use bullet points on tha plan.md to reduce git diff.
- The user may add tasks in the list.
- When switching to a new task put the task under "## In Progress" in the plan.md file.


## Completed

- [x] Rust crate with `hid`, `ctaphid`, `ctap2`, `tpm`, and `store` modules.
- [x] Virtual FIDO HID device over UHID with usage page `0xF1D0`, usage `0x01`, and 64-byte reports.
- [x] CTAPHID framing for `INIT`, `PING`, `CBOR`, `WINK`, `CANCEL`, and `ERROR`.
- [x] Browser registration and authentication working with TPM-backed CTAP2 credentials in SQLite.
- [x] `authenticatorGetInfo`, `authenticatorMakeCredential`, and `authenticatorGetAssertion` implemented.
- [x] `excludeList` rejection before prompting or creating TPM keys.
- [x] `allowList` handling, multi-assertion support, and `authenticatorGetNextAssertion`.
- [x] CTAP2 option validation for `up`, `uv`, and `rk`.
- [x] Local approval prompts for CTAP2 registration and authentication.
- [x] Development credentials persisted in a project-local SQLite store.
- [x] Startup logs the SQLite credential database path.
- [x] TPM probing for RNG and transient P-256 ECDSA signing.
- [x] TPM-backed P-256 credential creation and assertion signing.
- [x] Secure-boot PCR-bound credential creation and assertion.
- [x] Assertion sign counters persisted before success is returned.
- [x] SQLx offline metadata generated for compile-time query checking.
- [x] Dev shell exports `SQLX_OFFLINE=true`.
- [x] Holistic NixOS test boots a VM, starts the daemon, provisions a virtual TPM, completes register/assert, and verifies restart against the same SQLite store and TPM state.
- [x] treefmt-nix is wired in for `nix fmt` with `nixfmt`, `rustfmt`, and `taplo`.
- [x] Recovery slots can be generated during registration from `LINUX_TPM_FIDO2_RECOVERY_PASSPHRASE` and are persisted with the credential.
- [x] CTAP2 request handling accepts empty `allowCredentials` for discoverable passkey flows and rejects malformed `clientDataHash` lengths early.
- [x] SQLite storage now uses normalized metadata, keyslot, and token tables for CTAP2 credentials.
- [x] Daemon/user-session model is now explicit: a system daemon routes approvals against the active graphical session and logs session identity at startup.
- [x] GTK approval and settings UI prototype exists as a standalone GTK4 control surface.
- [x] CTAP2 requests with `uv=true` continue through the local approval flow instead of failing with `UnsupportedOption`.

## In Progress

## Next

- [ ] Improve CTAP2 request handling for browser edge cases.
- [ ] Add GTK approval and settings UI after transport, TPM, and storage are stable.

## Architecture Direction

- `hid` owns the UHID report descriptor and virtual HID identity.
- `ctaphid` owns HID packet framing, channel allocation, request assembly, and CTAPHID responses.
- `ctap2` owns CBOR command parsing, authenticator data, credential lookup, and assertion response shape.
- `store` owns the development SQLite credential schema and migrations and will evolve toward production metadata.
- `tpm` owns key creation/loading, signing, PCR policy sessions, recovery wrapping, and TPM capability checks.

## Open Design Questions

- The daemon should continue avoiding accidental cross-user credential sharing as GTK and session helpers are added.
- TPM-backed credential storage currently uses one TPM child key per credential; the production parent/policy model still needs a deliberate design.

## Non-Goals For Now

- No browser extension.
- No GTK until the non-GUI authenticator works with TPM-backed credentials.
- No claim of FIDO certification compatibility until the protocol is much more complete.
- No production security claims for the development credential store.
