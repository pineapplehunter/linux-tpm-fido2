#!/usr/bin/env bash
set -euo pipefail

mode="${1:?mode required}"
workdir="${WORKDIR:?WORKDIR required}"
rp_id="${RP_ID:-login.example.test}"
user_name="${USER_NAME:-alice}"
user_id="${USER_ID:-user-123}"
make_challenge="${MAKE_CHALLENGE:-make credential challenge}"
assert_challenge="${ASSERT_CHALLENGE:-assert credential challenge}"

mkdir -p "$workdir"

case "$mode" in
  register)
    python3 - "$workdir" "$rp_id" "$user_name" "$user_id" "$make_challenge" <<'PY'
import textwrap

exec(
    textwrap.dedent(
        """
        import cbor2
        import hashlib
        import sys
        import traceback
        from pathlib import Path

        from fido2.ctap2 import Ctap2
        from fido2.hid import CtapHidDevice

        try:
            workdir, rp_id, user_name, user_id, challenge = sys.argv[1:6]
            device = next(CtapHidDevice.list_devices())
            ctap = Ctap2(device)
            client_data_hash = hashlib.sha256(challenge.encode()).digest()
            print("python smoke: calling make_credential", file=sys.stderr, flush=True)
            attestation = ctap.make_credential(
                client_data_hash,
                {"id": rp_id, "name": rp_id},
                {"id": user_id.encode(), "name": user_name, "displayName": user_name},
                [{"type": "public-key", "alg": -7}],
                options={"rk": False, "up": True, "uv": False},
            )
            print("python smoke: make_credential returned", file=sys.stderr, flush=True)
            credential_data = attestation.auth_data.credential_data
            Path(workdir, "credential.id").write_bytes(credential_data.credential_id)
            with Path(workdir, "pubkey.cbor").open("wb") as stream:
                cbor2.dump(dict(credential_data.public_key), stream)
        except Exception:
            traceback.print_exc()
            raise
        """
    )
)
PY
  ;;
  assert)
    test -f "$workdir/pubkey.cbor"
    test -f "$workdir/credential.id"

    python3 - "$workdir" "$rp_id" "$assert_challenge" <<'PY'
import textwrap

exec(
    textwrap.dedent(
        """
        import cbor2
        import hashlib
        import sys
        import traceback
        from pathlib import Path

        from fido2.cose import CoseKey
        from fido2.ctap2 import Ctap2
        from fido2.hid import CtapHidDevice

        try:
            workdir, rp_id, challenge = sys.argv[1:4]
            device = next(CtapHidDevice.list_devices())
            ctap = Ctap2(device)
            client_data_hash = hashlib.sha256(challenge.encode()).digest()
            credential_id = Path(workdir, "credential.id").read_bytes()
            public_key = CoseKey.parse(cbor2.load(Path(workdir, "pubkey.cbor").open("rb")))
            print("python smoke: calling get_assertion", file=sys.stderr, flush=True)
            assertion = ctap.get_assertion(
                rp_id,
                client_data_hash,
                allow_list=[{"type": "public-key", "id": credential_id}],
                options={"up": True, "uv": False},
            )
            print("python smoke: get_assertion returned", file=sys.stderr, flush=True)
            assertion.verify(client_data_hash, public_key)
        except Exception:
            traceback.print_exc()
            raise
        """
    )
)
PY
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 2
  ;;
esac
