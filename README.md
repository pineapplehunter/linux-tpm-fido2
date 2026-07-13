# linux-tpm-fido2

`linux-tpm-fido2` is an experimental Linux TPM-backed FIDO2/WebAuthn authenticator.

It exposes a browser-usable virtual HID authenticator, stores credentials in SQLite, and uses the TPM for signing and recovery material.

## What It Does

- Presents a virtual FIDO2 HID authenticator to browsers.
- Creates TPM-backed P-256 credentials for registration and assertion.
- Supports secure-boot PCR-bound credentials.
- Supports recovery material unlocked by a passphrase and kept TPM-bound.
- Exposes a GTK4 control surface for approval and settings, including a modal approval popup and Unix peer checks.
- Uses a Unix-socket IPC seam between the daemon and the GTK control surface.

## Usage

Daemon:

```sh
linux-tpm-fido2 --store-dir .linux-tpm-fido2-store --tpm-path /dev/tpmrm0 --uhid-path /dev/uhid
```

GTK control surface:

```sh
linux-tpm-fido2-ui --store-dir .linux-tpm-fido2-store
```

Useful flags:

- `--dry-run` on the daemon prints the resolved configuration without opening devices.
- `--store-dir` selects the SQLite store and UI settings directory.

## Features

- CTAPHID framing for `INIT`, `PING`, `CBOR`, `WINK`, `CANCEL`, and `ERROR`.
- CTAP2 `authenticatorGetInfo`, `authenticatorMakeCredential`, and `authenticatorGetAssertion`.
- TPM-backed signing keys and PCR policy bindings.
- Recovery slots stored separately from the primary credential metadata.
- Sign counter persistence.
- GTK approval/settings prototype with TOML-backed preferences.
- Browser request compatibility for `credProps` and `residentKey` shapes.

## Future Work

- Expand CTAP2 compatibility for additional browser request shapes.
- Expand CTAP2 compatibility for additional browser request shapes.
- Harden the storage model toward production metadata and unlock mechanisms.
- Decide on the long-term daemon/session model before expanding the UI.
- Add a production threat model and security review before broad use.

## Current Limits

- Experimental only.
- No FIDO certification claims.
- No production security claims for the development store.
