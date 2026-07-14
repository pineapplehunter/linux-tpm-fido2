# Architecture

## Overview

`linux-tpm-fido2` is a system daemon that exposes a virtual FIDO2 authenticator to browsers through Linux UHID. The daemon owns the TPM-backed credential store, protocol handling, and approval flow. A separate GTK control surface provides the local settings and approval UI, backed by the same store directory and a Unix-socket IPC seam.

## Components

- Browser
- UHID virtual HID device
- `ctaphid`
- `ctap2`
- `store`
- `tpm`
- Daemon/session model
- GTK control surface
- Unix-socket IPC

## Request Flow

1. The browser talks to the authenticator over the virtual HID device.
2. `ctaphid` assembles HID packets into CTAPHID commands and dispatches them.
3. `ctap2` parses CBOR requests and performs credential selection, approval, and response assembly.
4. `tpm` creates signing keys, PCR-bound policies, and recovery material, then signs digests through the TPM.
5. `store` persists credential metadata, TPM key blobs, policy metadata, and recovery slots in SQLite.
6. The daemon records the active graphical session at startup and uses that context when it asks for approval.
7. The GTK control surface reads and writes UI preferences from `ui-settings.toml` and exposes a control socket at `control.sock` in the store directory.
8. The daemon logs the matching socket path and can later route approval prompts or settings requests to the GTK surface through IPC.

## Data Flow

- Browser-visible data: RP ID, user handle, sign counter, attestation/authenticator data, signatures.
- TPM data: P-256 key blobs, PCR policy binding, recovery key material.
- Store data: credential metadata, keyslots, tokens, and UI preferences.
- GTK data: pinned relying-party IDs, recovery label, approval prompts, and session context.

## Current Boundaries

- `hid` owns the report descriptor and device identity.
- `ctaphid` owns transport framing.
- `ctap2` owns WebAuthn/CTAP2 semantics.
- `tpm` owns TPM operations.
- `store` owns persistent credential state.
- `session` owns daemon session identity.
- `gtk_ui` owns the standalone GTK control surface.
- `ipc` owns the Unix-socket seam between the daemon and GTK surface.

## Future Integration

- The daemon should eventually hand approval prompts to the GTK surface over IPC instead of using the current terminal-based approval path.
- The GTK surface should eventually become the daemon-facing approval/settings UI.
- A later architecture pass should decide whether user scoping stays session-based or becomes per-user/per-session daemon instances.
