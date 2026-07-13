# Implementation Plan

## Current State

- Rust crate exists with core modules for `hid`, `ctaphid`, `ctap2`, `tpm`, and `store`.
- The daemon presents a Linux UHID virtual FIDO HID device using usage page `0xF1D0`, usage `0x01`, and 64-byte reports.
- CTAPHID framing works for `INIT`, `PING`, `CBOR`, `WINK`, `CANCEL`, and `ERROR`.
- Browser registration and authentication work in Firefox with TPM-backed CTAP2 credentials persisted in SQLite.
- CTAP2 works through `CTAPHID_CBOR` with `authenticatorGetInfo`, `authenticatorMakeCredential`, and `authenticatorGetAssertion`.
- `authenticatorMakeCredential` handles `excludeList` for existing credentials and returns `CTAP2_ERR_CREDENTIAL_EXCLUDED` before prompting or creating TPM keys.
- `authenticatorGetAssertion` handles absent, empty, matching, and non-matching `allowList` descriptors.
- CLI yes/no prompts provide early user-presence approval for CTAP2 registration/authentication.
- Development credentials are persisted in a project-local, git-ignored store.
- Startup logs the exact SQLite credential database path.
- The dev shell includes `tpm2-tss`, and the Rust crate links `tss-esapi`.
- Runtime TPM probing can open `/dev/tpmrm0`, read TPM RNG output, create a transient P-256 ECDSA signing key, and sign a test digest.
- CTAP2 creates TPM-backed P-256 credentials, storing TPM private/public blobs plus public coordinates.
- CTAP2 assertion signs with TPM-backed credentials and persists the next signature counter to SQLite before returning a successful response.
- PCR binding, recovery slots, durable production metadata, and GUI are not implemented yet.

## Credential Store

- Default store directory: `.linux-tpm-fido2-store`.
- Override store directory with `--store-dir <path>`.
- CTAP2 TPM-backed credentials are saved to `credentials.sqlite`.
- SQLite schema changes are managed with `sqlx` migrations in `migrations/`.
- Registration saves credential metadata and TPM blobs transactionally.
- Assertion updates only the matched credential's `sign_count` row.
- The SQLite format is still development storage and must not be treated as production metadata.

## Near-Term Workflow

- Run without touching devices: `nix develop -c cargo run -- --dry-run`.
- Run against UHID/TPM defaults: `nix develop -c cargo run`.
- Use `RUST_LOG=debug` when diagnosing CTAPHID traffic.
- Use a known test store when debugging persistence: `nix develop -c cargo run -- --store-dir /tmp/linux-tpm-fido2-store`.
- Verify changes with `nix develop -c cargo fmt -- --check`, `nix develop -c cargo check`, and `nix develop -c cargo test`.

## Next Milestones

1. Test TPM-backed CTAP2 registration/login against Chrome, including daemon restart.
2. Improve CTAP2 request handling enough for robust browser behavior: options, user presence flags, request validation, multiple assertion responses, and better CTAP status codes.
3. Add PCR-bound credential creation and assertion, starting with secure boot state.
4. Add recovery slots using passphrase-unlocked material that remains TPM-bound but is not PCR-bound.
5. Evolve the SQLite schema toward LUKS2-inspired keyslots, tokens, policy descriptors, digests, and recovery metadata.
6. Design the daemon/user-session model before GTK: decide whether this is per-user, system broker plus per-user helper, or active-session routed.
7. Add GTK approval and settings UI after the transport, TPM, and storage model are stable.

## Architecture Direction

- `hid` owns the UHID report descriptor and virtual HID identity.
- `ctaphid` owns HID packet framing, channel allocation, request assembly, and CTAPHID responses.
- `ctap2` owns CBOR command parsing, authenticator data, credential lookup, and assertion response shape.
- `store` owns the development SQLite credential schema and migrations and will evolve toward production metadata.
- `tpm` should own key creation/loading, signing, PCR policy sessions, recovery wrapping, and TPM capability checks.

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
