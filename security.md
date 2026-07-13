# Security

## Scope

This project is an experimental TPM-backed FIDO2/WebAuthn authenticator daemon with a GTK control surface and a local SQLite store.

## Assets

- TPM private blobs for CTAP2 credentials.
- TPM private blobs for recovery key material.
- PCR policy bindings.
- Credential metadata and sign counters in SQLite.
- UI settings in `ui-settings.toml`.
- Approval decisions and session identity.

## Trust Boundaries

- Browser to UHID/CTAPHID/CTAP2 request path.
- Daemon to TPM device access.
- Daemon to SQLite store access.
- Daemon to GTK control surface IPC.
- Local desktop session identity and approval prompts.

## Threats

- Malicious web page or browser origin attempting unauthorized credential creation or assertion.
- Local unprivileged user trying to read or tamper with the credential store.
- Local process trying to talk to the GTK control socket and influence settings or approvals.
- Replay or reuse of stale approval state.
- TPM or firmware compromise that undermines credential secrecy.
- Physical machine compromise that exposes the store directory or the TPM device.

## Current Mitigations

- Browser requests are constrained by CTAP2 parsing, allow/exclude list handling, clientDataHash validation, and user approval prompts.
- Credentials are TPM-backed rather than software-key backed.
- Secure-boot PCR policy can bind credentials to boot state.
- Recovery material remains TPM-bound and is stored separately from the main credential metadata.
- Sign counters are persisted after successful assertions.
- The GTK control surface stores settings in a dedicated TOML file and exposes a Unix-socket seam in the store directory.

## Known Gaps

- The daemon-side GTK IPC auth story now checks Unix peer credentials, but broader policy review is still warranted.
- The session/user binding model is still evolving.
- The approval path is still partially terminal-driven in the daemon.
- The store layout is still development-oriented and not hardened for production use.
- There is no claim of FIDO certification compatibility or production-grade security.

## Future Work

- Define and enforce IPC authentication for the GTK control socket. The current server now checks peer credentials and rejects unauthorized clients.
- Decide between per-user daemon, per-session helper, or another user-namespace strategy.
- Add explicit permission checks around any approval/settings API.
- Consider stronger anti-rollback or monotonic counter strategies if the threat model requires it.
- Revisit storage encryption and recovery-token handling before production use.
