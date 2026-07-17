import sys
import traceback
from base64 import b64decode
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement

PERM_CRED_MGMT = 4

if __name__ == "__main__":
    try:
        dev = next(CtapHidDevice.list_devices())
        ctap = Ctap2(dev)
        pin = ClientPin(ctap)
        pin.set_pin("tpass")
        token = pin.get_pin_token("tpass", permissions=PERM_CRED_MGMT)
        if not token:
            raise RuntimeError("no token")
        credman = CredentialManagement(ctap, pin.protocol, token)
        credman.delete_cred({"type": "public-key", "id": b64decode(sys.argv[1])})
    except Exception:
        traceback.print_exc()
        sys.exit(1)
