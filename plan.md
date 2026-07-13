# Implementation Plan

## Current State

- Rust crate exists with core modules for `hid`, `ctaphid`, `ctap2`, `tpm`, and `store`.
- The daemon presents a Linux UHID virtual FIDO HID device using usage page `0xF1D0`, usage `0x01`, and 64-byte reports.
- CTAPHID framing works for `INIT`, `PING`, `MSG`, `CBOR`, `WINK`, `CANCEL`, and `ERROR`.
- Browser registration and authentication work in Firefox and Chrome through the current software authenticator paths.
- U2F compatibility works through `CTAPHID_MSG` with software P-256 credentials.
- Minimal CTAP2 works through `CTAPHID_CBOR` with `authenticatorGetInfo`, `authenticatorMakeCredential`, and `authenticatorGetAssertion`.
- CLI yes/no prompts provide early user-presence approval for U2F and CTAP2 registration/authentication.
- Development credentials are persisted in a project-local, git-ignored store.
- Startup logs the exact credential file paths.
- TPM signing, PCR binding, recovery slots, durable production metadata, and GUI are not implemented yet.

## Credential Files

- Default store directory: `.linux-tpm-fido2-store`.
- Override store directory with `--store-dir <path>`.
- U2F software credentials are saved to `u2f-credentials.json`.
- CTAP2 software credentials are saved to `ctap2-credentials.json`.
- These files currently contain development software private keys and must not be treated as secure production storage.

## Near-Term Workflow

- Run without touching devices: `nix develop -c cargo run -- --dry-run`.
- Run against UHID/TPM defaults: `nix develop -c cargo run`.
- Use `RUST_LOG=debug` when diagnosing CTAPHID traffic.
- Use a known test store when debugging persistence: `nix develop -c cargo run -- --store-dir /tmp/linux-tpm-fido2-store`.
- Verify changes with `nix develop -c cargo fmt -- --check`, `nix develop -c cargo check`, and `nix develop -c cargo test`.

## Next Milestones

1. Replace software CTAP2 signing with TPM 2.0 ECC P-256 signing keys via `tss-esapi`.
2. Store TPM public/private blobs and credential metadata instead of CTAP2 software private keys.
3. Improve CTAP2 request handling enough for robust browser behavior: options, exclude list, allow list edge cases, user presence flags, and better CTAP status codes.
4. Replace U2F software signing with TPM-backed signing or decide whether to keep U2F as a development-only compatibility path.
5. Add signature-counter persistence semantics that are safe across crashes and failed writes.
6. Add PCR-bound credential creation and assertion, starting with secure boot state.
7. Add recovery slots using passphrase-unlocked material that remains TPM-bound but is not PCR-bound.
8. Move from development JSON files toward a LUKS2-inspired credential metadata format with keyslots, tokens, digests, and atomic writes.
9. Design the daemon/user-session model before GTK: decide whether this is per-user, system broker plus per-user helper, or active-session routed.
10. Add GTK approval and settings UI after the transport, TPM, and storage model are stable.

## Architecture Direction

- `hid` owns the UHID report descriptor and virtual HID identity.
- `ctaphid` owns HID packet framing, channel allocation, request assembly, U2F compatibility, and CTAPHID responses.
- `ctap2` owns CBOR command parsing, authenticator data, credential lookup, and assertion response shape.
- `store` owns the development credential file format and will evolve toward production metadata.
- `tpm` should own key creation/loading, signing, PCR policy sessions, recovery wrapping, and TPM capability checks.

## Open Design Questions

- Per-user credential binding needs a deliberate design. A system daemon receiving raw HID traffic does not automatically know which Unix user or browser process initiated a CTAP request.
- Possible user-binding designs include a per-user daemon that creates a per-session virtual authenticator, a privileged system broker with per-user/session helpers, or a system daemon that routes requests to the active graphical session for approval and credential namespace selection.
- The service model should avoid making all users share one credential namespace unless that is explicitly intended.
- TPM-backed credential storage needs a decision on whether each credential is its own TPM key, a TPM-wrapped software key, or a hybrid model during development.

## Non-Goals For Now

- No browser extension.
- No GTK until the non-GUI authenticator works with TPM-backed credentials.
- No claim of FIDO certification compatibility until the protocol is much more complete.
- No production security claims for the development software credential store.
