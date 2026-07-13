# Implementation Plan

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
- [x] Assertion sign counters persisted before success is returned.
- [x] SQLx offline metadata generated for compile-time query checking.
- [x] Dev shell exports `SQLX_OFFLINE=true`.

## In Progress

- [ ] Add a holistic NixOS test that boots a VM, starts the daemon, provisions a virtual TPM, and drives the authenticator end-to-end.

## Next

1. [ ] Run the holistic NixOS test against credential registration and login.
2. [ ] Verify daemon restart with the same SQLite store and TPM state.
3. [ ] Improve CTAP2 request handling for browser edge cases.
4. [ ] Add PCR-bound credential creation and assertion, starting with secure boot state.
5. [ ] Add recovery slots using passphrase-unlocked TPM-bound material.
6. [ ] Evolve the SQLite schema toward LUKS2-style metadata, tokens, and keyslots.
7. [ ] Decide the daemon/user-session model before GTK work.
8. [ ] Add GTK approval and settings UI after transport, TPM, and storage are stable.

## Architecture Direction

- `hid` owns the UHID report descriptor and virtual HID identity.
- `ctaphid` owns HID packet framing, channel allocation, request assembly, and CTAPHID responses.
- `ctap2` owns CBOR command parsing, authenticator data, credential lookup, and assertion response shape.
- `store` owns the development SQLite credential schema and migrations and will evolve toward production metadata.
- `tpm` owns key creation/loading, signing, PCR policy sessions, recovery wrapping, and TPM capability checks.

## Open Design Questions

- Per-user credential binding needs a deliberate design. A system daemon receiving raw HID traffic does not automatically know which Unix user or browser process initiated a CTAP request.
- Possible user-binding designs include a per-user daemon that creates a per-session virtual authenticator, a privileged system broker with per-user/session helpers, or a system daemon that routes requests to the active graphical session for approval and credential namespace selection.
- The service model should avoid making all users share one credential namespace unless that is explicitly intended.
- TPM-backed credential storage currently uses one TPM child key per credential; the production parent/policy model still needs a deliberate design.

## Non-Goals For Now

- No browser extension.
- No GTK until the non-GUI authenticator works with TPM-backed credentials.
- No claim of FIDO certification compatibility until the protocol is much more complete.
- No production security claims for the development credential store.
