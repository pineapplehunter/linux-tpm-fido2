# Architecture

## Overview

`linux-tpm-fido2` is a system daemon that exposes a virtual FIDO2 authenticator to browsers through Linux UHID. The daemon owns the TPM-backed credential store, protocol handling, and approval flow. Approval prompts fall back to stdin/stdout; future versions will integrate polkit for authorization.

## Components

- Browser
- UHID virtual HID device
- `ctaphid`
- `ctap2`
- `store`
- `tpm`
- Daemon/session model
- Polkit authorization
- Unix-socket IPC

## Request Flow

1. The browser talks to the authenticator over the virtual HID device.
2. `ctaphid` assembles HID packets into CTAPHID commands and dispatches them.
3. `ctap2` parses CBOR requests and performs credential selection, approval, and response assembly.
4. `tpm` creates signing keys, PCR-bound policies, and recovery material, then signs digests through the TPM.
5. `store` persists credential metadata, TPM key blobs, policy metadata, and recovery slots in SQLite.
6. The daemon records the active graphical session at startup and uses that context when it asks for approval.
7. *(Reserved for polkit integration)*

## Data Flow

- Browser-visible data: RP ID, user handle, sign counter, attestation/authenticator data, signatures.
- TPM data: P-256 key blobs, PCR policy binding, recovery key material.
- Store data: credential metadata, keyslots, tokens, and UI preferences.


## Current Boundaries

- `hid` owns the report descriptor and device identity.
- `ctaphid` owns transport framing.
- `ctap2` owns WebAuthn/CTAP2 semantics.
- `tpm` owns TPM operations.
- `store` owns persistent credential state.
- `session` owns daemon session identity.
- `ipc` owns the Unix-socket seam for communication with external authorizers.

## Future Integration

- A later architecture pass should decide whether user scoping stays session-based or becomes per-user/per-session daemon instances.
