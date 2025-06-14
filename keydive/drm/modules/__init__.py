import logging
from typing import List, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

from keydive.drm.keybox import KeyBox
from keydive.drm.protocol.license_pb2 import ClientIdentification


class BaseCdm:

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.sdk = 36
        self.disabler = True

        self._device_aes_key: List[bytes] = []
        self._keybox: Dict[bytes, KeyBox] = {}  # stable_id -> keybox

        self._client_id: Dict[int, ClientIdentification] = {}  # public_key.n -> client_id
        self._certificate: Dict[int, List[Certificate]] = {}  # public_key.n -> oem_certificate
        self._private_key: Dict[int, RSAPrivateKey] = {}  # public_key.n -> private_key

        # Cached ClientIdentification instance representing the device’s current provisioning context
        # This may be reused across multiple requests to avoid re-parsing
        self._provisioning: Optional[ClientIdentification] = None
        self._context: Optional[bytes] = None
