# Implementation Plan

## How to use this file

Use this file as a todolist with context.
This section has the task list.
Tasks that need to be worked on should be in "Next Tasks".
Move the task to "In Progress" when starting working on it.
Move the task to the end of "Completed" when finished with a timestamp like "(finished YY-MM-DD HH:mm)".

### In Progress

- [x] Fix polkit action ID mismatch: code uses `org.linux_tpm_fido2.approve`, policy now matches.

### Next Tasks

- [ ] Evaluate whether the Unix-socket IPC control surface (ipc.rs) has ongoing value or should be removed alongside the GTK frontend.
- [ ] Refactor NixOS test to use `virtualisation.tpm.enable` instead of manual swtpm CUSE setup — eliminates `modprobe cuse` dependency and simplifies the test script.

### Completed

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
- [x] GTK approval IPC now blocks on a user decision instead of auto-approving requests when the UI is running.
- [x] GTK control socket authenticates peers with Unix peer credentials before honoring settings or approval requests.
- [x] CTAP2 requests with `uv=true` continue through the local approval flow instead of failing with `UnsupportedOption`.
- [x] CTAP2 getInfo advertises `credProps` and makeCredential returns the `credProps` extension when requested.
- [x] CTAP2 makeCredential accepts the browser attestation conveyance preference shape.
- [x] Approval prompts surface IPC peer process metadata alongside the session identity.
- [x] GTK control surface exposes a Unix-socket IPC seam and the daemon logs the matching socket path.
- [x] `architecture.md` explains the browser, device, daemon, GTK, and IPC interactions.
- [x] `security.md` captures the current threat model, mitigations, and future work.
- [x] CTAP2 requests with `up=false` are rejected instead of silently continuing.
- [x] README focuses on project purpose, usage, features, and future work.
- [x] GTK frontend removed; approval falls back to stdin/stdout; polkit integration planned.
- [x] Add GTK approval and settings UI after transport, TPM, and storage are stable.
- [x] Fix sqlx migration. The normalized schema is now in place and the store round-trips under tests.
- [x] Eliminate approval-reuse grace period in CTAP2 assertions (2026-07-14 21:24).
- [x] Switch passphrase hashing from SHA-256 to PBKDF2-HMAC-SHA256 (2026-07-14 21:27).
- [x] Set TPM auth value on PCR-bound credential keys (2026-07-14 21:42).
- [x] Document rollback behavior and mitigations in security.md (2026-07-14 21:43).
- [x] Remove GTK frontend code and dependencies (2026-07-14 21:48).
- [x] Add HMAC-SHA256 integrity protection for credential metadata (2026-07-14 21:56).
- [x] Add systemd-logind integration for dynamic session detection (2026-07-14 22:00).
- [x] Add session verification before and after approval (2026-07-14 22:07).
- [x] Add LINUX_TPM_FIDO2_AUTO_APPROVE env var for testing (2026-07-14 22:08).
- [x] Add prominent warning when LINUX_TPM_FIDO2_AUTO_APPROVE is set (2026-07-14 22:11).
- [x] Implement polkit authorization in approval flow (2026-07-14 22:17).
- [x] Refactor CTAP2 and CTAPHID command/error constants into enums (2026-07-14 22:26).
- [x] Add NixOS module and update test to use it; reboot test verifies credential persistence (2026-07-14 22:30).
- [x] Investigated virtualisation.tpm.enable — swtpm CUSE approach is correct for QEMU-less VM TPM provisioning.
- [x] Bind UHID device to active sessions via uaccess in tpm-fido2.rules.

## General things to keep in mind.
- Commit the changes to git after a task
- Do these tests
    - cargo check
    - cargo test
    - nixos test
    - nix fmt
- Fixup cargo clippy after a POC implementation
- When writing bash scripts for nix, generally keep the script in a separate file and use lib.readFile to import it.
- Create a todolist with the todowrite tool for each task to keep track of progress. The last task should be "Start next task in plan.md" which should update the todolist with the next task.
- Update README and AGENTS.md when a new feature gets implemented or the implementation changed from the original docs.
- Use bullet points on tha plan.md to reduce git diff.
- The user may add tasks in the list.
- When switching to a new task put the task under "## In Progress" in the plan.md file.
- When the current task is moderately large split them up into subtasks and prepenthem in the "Next Tasks" Section
- The "Next Tasks" section should not have any items that are done. If there are, check if they are actually done and if so, move them to Completed.


## Security model design

The [security model](../docs/security.md#current-implementation-status) lists nine issues that must be resolved before production security claims are made.

- [x] Remove approval-reuse grace period in CTAP2 assertions.
- [x] Switch passphrase hashing from SHA-256 to an offline-resistant KDF (PBKDF2/argon2).
- [x] Set a non-empty TPM auth value on PCR-bound credential keys to prevent empty-auth bypass.
- [x] Obtain session identity dynamically from `systemd-logind` instead of environment variables.
- [x] Bind UHID device generations to active sessions with `uaccess` (udev rule already matches with `TAG+="uaccess"`).
- [x] Verify session identity before and after approval interaction.
- [x] Add integrity protection (HMAC/AEAD) for stored credential metadata.
- [x] Document rollback behavior and mitigations.
- [x] Integrate polkit authorization calls into the daemon at runtime.


## Architecture Direction

- `hid` owns the UHID report descriptor and virtual HID identity.
- `ctaphid` owns HID packet framing, channel allocation, request assembly, and CTAPHID responses.
- `ctap2` owns CBOR command parsing, authenticator data, credential lookup, and assertion response shape.
- `store` owns the development SQLite credential schema and migrations and will evolve toward production metadata.
- `tpm` owns key creation/loading, signing, PCR policy sessions, recovery wrapping, and TPM capability checks.

## Non-Goals For Now

- No browser extension.
- No GTK frontedn use polkit.
- No claim of FIDO certification compatibility until the protocol is much more complete.
- No production security claims for the development credential store.
