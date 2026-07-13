# Credential Storage

This document describes the current credential storage model and the intended future direction.

## Current Implementation

### Scope

The current implementation stores only CTAP2/WebAuthn credentials backed by TPM-created P-256 ECDSA keys.

U2F/CTAP1 support has been removed.

Software credential support has been removed.

### Store Location

Credentials are stored in a project-local directory by default:

```text
.linux-tpm-fido2-store/
```

The store directory can be overridden at runtime:

```sh
linux-tpm-fido2 --store-dir /path/to/store
```

Startup logs the resolved credential file path.

### Files

The current implementation uses one JSON file:

```text
.linux-tpm-fido2-store/ctap2-credentials.json
```

All binary values are base64-encoded JSON strings.

The store directory is git-ignored.

### CTAP2 TPM Credentials

Each credential record contains WebAuthn metadata plus TPM key blobs:

```json
{
  "id": "base64 credential ID",
  "rp_id": "example.com",
  "user_handle": "base64 user handle",
  "user_name": "optional username",
  "user_display_name": "optional display name",
  "tpm_private": "base64 TPM2B_PRIVATE blob",
  "tpm_public": "base64 marshalled TPMT_PUBLIC blob",
  "public_key_x": "base64 P-256 x coordinate",
  "public_key_y": "base64 P-256 y coordinate",
  "sign_count": 0
}
```

Behavior:

- During registration, the daemon creates a TPM P-256 ECDSA signing key.
- The TPM returns private/public blobs for the credential key.
- `tpm_private` and `tpm_public` are saved so the key can be loaded later.
- `public_key_x` and `public_key_y` are saved for WebAuthn COSE public key material.
- During assertion, the daemon creates a transient storage parent, loads the credential key blobs, signs the assertion digest in the TPM, then flushes transient TPM handles.
- `sign_count` is incremented after assertion signing and persisted back to JSON.

Current TPM parent strategy:

- The daemon uses a transient owner-hierarchy storage parent.
- The parent is recreated as needed.
- Child credential blobs are loadable under that parent template.

Current failure behavior:

- If TPM is unavailable, new CTAP2 credential creation fails.
- If a stored TPM credential cannot be loaded or signed, assertion fails.
- There is no software fallback.

Security status:

- TPM private blobs are not raw private keys, but this is still development storage.
- There is no PCR policy yet.
- There is no recovery design yet.
- JSON writes are not atomic yet.
- Metadata is not authenticated as a complete structure yet.

## Current Limitations

- The JSON store is intentionally simple and development-oriented.
- Signature-counter updates are simple rewrites and are not crash-safe.
- TPM-backed credentials are not PCR-bound yet.
- TPM-backed credentials do not yet have passphrase recovery slots.
- There is no per-user namespace design yet.
- There is no integrity protection over the metadata file as a whole.
- Old development stores containing software records should be deleted or recreated.

## Future Improvements

### Production Metadata Format

Credential storage should evolve toward a LUKS2-inspired metadata format:

- Structured JSON metadata with a clear schema version.
- Atomic writes with temporary files and rename.
- Metadata checksums or authenticated digests.
- Duplicated metadata areas or recoverable metadata updates.
- Clear separation between credential metadata, encrypted secrets, keyslots, tokens, and policy descriptors.

### TPM-Backed Credentials

Future TPM-backed credential records should include:

- TPM public/private blobs.
- Parent key template or parent key identifier.
- Algorithm identifiers.
- Credential creation policy.
- PCR policy description.
- Recovery policy description.
- RP/user metadata.
- Signature counter state.

The daemon should not store raw software private keys for production credentials.

### PCR Binding

The first production TPM policy target should be secure-boot-state binding.

Future records should describe:

- Hash algorithm.
- PCR selection.
- Expected PCR policy digest.
- Whether the credential is boot-state-bound.
- Whether the credential has a recovery path.

### Recovery

Recovery should use passphrase-unlocked material that remains TPM-bound but is not PCR-bound.

Future recovery metadata should include:

- Keyslot descriptors.
- KDF parameters.
- TPM-wrapped recovery material.
- Recovery token metadata.
- Rotation and revocation support.

### Counters And Durability

Signature counters should be updated safely.

Future improvements should include:

- Atomic counter writes.
- Clear behavior for failed writes after successful signing.
- Possibly monotonic TPM NV counters or another anti-rollback strategy if needed.

### User Namespaces

The storage model must be tied to the daemon/user-session design.

Open options:

- Per-user daemon with per-user credential store.
- System daemon plus per-user helper.
- System daemon routing requests to the active graphical session.

The production design should avoid accidentally sharing one credential namespace across all local users.
