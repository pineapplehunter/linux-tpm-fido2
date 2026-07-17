# Agent Notes

## Repository State

- This repo is starting a Linux TPM-backed FIDO2/WebAuthn passkey daemon; `README.md` is the current product sketch.
- A Rust crate now exists. The current implementation is not fully compatible with the fido2 spec, but works on webauthn.io.
- TPM signing, credential registration/assertion, persistent credential storage, and recovery-slot generation are implemented.
- GUI is not planned.
- CTAP2 credential storage records a `user_id` and the daemon prefers `SUDO_UID` when running under sudo so credentials can be scoped to the connected user.
- CTAP2 / Client-to-Authenticator spec reference (FIDO Proposed Standard, July 2025): https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html
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

## Known Issues / Debugging History

### NixOS VM test only uses `/dev/tpm0` (no `/dev/tpmrm0`)

The test VM (`nix/nixos-test-polkit.nix`) uses `virtualisation.tpm.enable = true` (swtpm),
which provides `/dev/tpm0` but *not* `/dev/tpmrm0`.  On bare metal with a real TPM 2.0,
the kernel resource-manager driver (`tpmrm`) creates `/dev/tpmrm0`, which supports
multiple simultaneous openers.  The daemon defaults to `/dev/tpmrm0` in its CLI args,
but the test VM explicitly uses `/dev/tpm0`.

Since `/dev/tpm0` only allows **one** opener at a time, management subcommands that
try to open a second TPM context (e.g. `update-pcr-reference`) fail with
`Tss2_Tcti_Device_Init() … Device or resource busy`.

### Fix: TPM command channel (management → main daemon thread)

Management commands that need TPM access now send a `TpmCommand` over an
`mpsc` channel to the main daemon loop, which owns the lone TPM context.

Relevant types in `src/ctap2.rs`:
  - `TpmCommand::PcrPolicyUpdate(PcrPolicyUpdateCommand)`
  - `Authenticator::handle_tpm_command(&mut self, TpmCommand)`
  - `TpmCmdSender` / `TpmCmdResult`

**`src/main.rs`**:
  - Creates an `mpsc` channel before spawning the management server.
  - Every loop iteration calls `tpm_cmd_rx.try_recv()` and, if a command
    is pending, dispatches it to `ctaphid.handle_tpm_command()`.

**`src/management.rs`**:
  - `serve()` now accepts `Option<TpmCmdSender>` instead of a TPM device path.
  - `handle_update_pcr_reference()` validates the passphrase in the management
    thread, then sends the actual TPM work to the daemon thread.
  - Falls back to the old direct-TPM-open path when no channel is available
    (e.g. during unit tests).

### PinUvAuthProtocol 2 token response (getPinUvAuthToken / getPinUvAuthTokenUsingUv)

Per CTAP 2.2 §6.5.7, the `getPinUvAuthToken` and `getPinUvAuthTokenUsingUv`
responses MUST contain key 2 (encrypted token) **and** key 3
(`pinUvAuthParam` = HMAC-SHA256(mac_key, encrypted_token)[0..16]).  Key 3 was
temporarily removed during a debugging session because Chrome appeared to
disconnect on the larger (71-byte) response, but that was not caused by key 3
itself — it is now re-added in `src/ctap2.rs` via
`compute_pin_uv_auth_param`.

`derive_protocol2_keys` uses info strings `b"CTAP2 AES key"` and
`b"CTAP2 HMAC key"` with a 32-byte zero salt — NO trailing null byte
(confirmed against CTAP 2.2 spec and the companion Python reference impl).

makeCredential `pinUvAuthParam` HMAC message = `clientDataHash || rpId` and the
token must be scoped to `Some(rp_id)`; getAssertion message = `clientDataHash`.
Regression test: `make_credential_with_pin_uv_auth_token_regression`.

### CTAP2 command enumeration (CTAP 2.2 §6 Authenticator API)

Enumerated against the spec; current status in `src/ctap2.rs`:

| Command | Code | Status |
| --- | --- | --- |
| authenticatorMakeCredential | 0x01 | Implemented |
| authenticatorGetAssertion | 0x02 | Implemented |
| authenticatorGetNextAssertion | 0x08 | Implemented (stateful) |
| authenticatorGetInfo | 0x04 | Implemented |
| authenticatorClientPIN | 0x06 | Implemented (sub 1,2,3,4,6,9,10) |
| authenticatorCredentialManagement | 0x0A | Implemented (sub 1-7) + preview 0x41 |
| authenticatorReset | 0x07 | Implemented (deletes credentials + PIN after approval) |
| authenticatorSelection | 0x0B | Implemented (returns empty success after approval) |
| authenticatorBioEnrollment | 0x09 | `todo!()` — no built-in biometric UV method |
| authenticatorLargeBlobs | 0x0C | `todo!()` — large blob storage not implemented |
| authenticatorConfig | 0x0D | `todo!()` — enterprise attestation / alwaysUv / minPINLength |
| authenticatorBioEnrollmentPreview | 0x40 | aliases BioEnrollment (`todo!()`) |

CTAPHID mandatory commands (§11.2.9.1: MSG, CBOR, INIT, PING, CANCEL, ERROR,
KEEPALIVE) are handled in `src/ctaphid.rs`. WINK/LOCK are optional.

### Correctness issues found during CTAP2 review

- **getAssertion UP flag is hardcoded.** `make_auth_data` is called with a
  fixed `0x01` UP bit in `get_assertion` (`src/ctap2.rs:~555`), so pre-flight
  assertions requested with `up=false` still report UP=1. Per §6.2.2 the UP bit
  MUST be 0 when user presence was not requested. `make_credential` likewise
  hardcodes UP (acceptable there since approval grants presence, but the
  `up` option is not validated for CTAP2.0 `up=false` rejection).
- **getInfo `uv` option is `false` while `pinUvAuthToken` is `true`.** Spec
  §6.4 requires `pinUvAuthToken: true` ⟺ (`clientPin: true` OR `uv: true`).
  This passes only because `clientPin` may be true; it is inconsistent for the
  no-PIN case. Consider advertising `uv: true` (PIN-based UV is a form of UV)
  or gating `pinUvAuthToken` on `clientPin.is_some()`.
- **`makeCredUvNotRqd` is not advertised.** A CTAP2.1 authenticator that
  supports clientPIN but does not require UV for non-discoverable credentials
  SHOULD advertise `makeCredUvNotRqd: true` (§6.4, §9). Not currently sent.
- **`getInfo` version list / extensions.** `versions` advertises
  `["FIDO_2_1","FIDO_2_0"]`; `extensions` only lists `credProps`. hmac-secret,
  credBlob, largeBlobKey, minPinLength are not implemented/advertised.
- **Reset/BioEnrollment/LargeBlobs/Config** were missing entirely from the
  command enum until added with `todo!()` (non-trivial ones) and real
  implementations (Reset, Selection).

### Debug logging in TPM operations

The file `src/tpm.rs` contains several `log::debug!` calls that trace
PCR-digest computation, policy-authorize signing, and the assertion TPM
flow.  They are inactive at the default `info` log level and can be
seen by setting `RUST_LOG=debug`.
