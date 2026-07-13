# Implementation Plan

## Initial Scope

- Start without GUI.
- Prove browser-visible FIDO2 transport first.
- Keep the first authenticator intentionally small before adding TPM policy, storage recovery, and settings.
- Early development should be runnable with `sudo` for debugging, with a goal of moving to a dedicated daemon user later.
- Target real TPM access first through `/dev/tpmrm0` via `tss-esapi`.
- Use a CLI yes/no prompt for early user presence approval.
- Use a project-local ignored credential store during development.
- Validate browser behavior against Firefox on Linux first.

## Milestones

1. Create a Rust crate with core modules for `hid`, `ctaphid`, `ctap2`, `tpm`, and `store`.
2. Implement a Linux UHID virtual HID device using the FIDO usage page `0xF1D0` and CTAPHID usage `0x01`.
3. Implement CTAPHID framing and transaction handling for `INIT`, `PING`, `ERROR`, and `CANCEL`.
4. Add `CTAPHID_CBOR` transport and a minimal CTAP2 `authenticatorGetInfo` response.
5. Implement `authenticatorMakeCredential` and `authenticatorGetAssertion` with temporary software P-256 keys to validate CTAP2/WebAuthn behavior before involving TPM complexity.
6. Replace software signing with TPM 2.0 ECC P-256 signing keys via `tss-esapi`.
7. Add an on-disk credential store for public credential metadata, TPM public/private blobs, signature counters, RP/user metadata, and policy descriptors.
8. Add PCR-bound credential creation and assertion, starting with secure boot state and leaving room for configurable PCR selections.
9. Add passphrase recovery slots using TPM-bound but non-PCR-bound wrapping material.
10. Add a non-GUI local approval mechanism for user presence during early development.
11. Add GTK approval and settings UI after the transport, TPM, and storage model are working.

## Open Design Questions

- Per-user credential binding needs a deliberate design. A system daemon receiving raw HID traffic does not automatically know which Unix user or browser process initiated a CTAP request.
- Possible user-binding designs include a per-user daemon that creates a per-session virtual authenticator, a privileged system broker with per-user/session helpers, or a system daemon that routes requests to the active graphical session for approval and credential namespace selection.
- The dedicated-user service model should avoid making all users share one credential namespace unless that is explicitly intended.

## Architecture Direction

- The daemon presents a virtual FIDO2 HID authenticator to browsers through `/dev/uhid`.
- CTAPHID owns HID packet framing, channel allocation, transaction timeouts, keepalive, and cancellation.
- CTAP2 owns CBOR command parsing, authenticator data, attestation response shape, credential lookup, and assertion signing.
- TPM code owns key creation/loading, signing, PCR policy sessions, recovery wrapping, and TPM capability checks.
- Storage should be a LUKS2-inspired metadata file rather than TPM NV storage: duplicated metadata, JSON structure, keyslots/tokens, digests, and serialized updates.

## Early Non-Goals

- No browser extension.
- No GTK until the non-GUI authenticator works.
- No CTAP1/U2F compatibility in the first implementation.
- No advanced CTAP2 extensions until basic registration and authentication work.
- No claim of FIDO certification compatibility until the protocol is much more complete.
