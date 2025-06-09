from enum import Enum
from typing import Optional

from construct import BitStruct, Bytes, Const
from construct import Enum as CEnum
from construct import Int8ub, Int16ub
from construct import Optional as COptional
from construct import Padded, Padding, Struct, this
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from keydive.drm.protocol.license_pb2 import ClientIdentification


class DeviceTypes(Enum):
    CHROME = 1
    ANDROID = 2


class _Structures:
    magic = Const(b"WVD")

    header = Struct(
        "signature" / magic,
        "version" / Int8ub
    )

    v2 = Struct(
        "signature" / magic,
        "version" / Const(2, Int8ub),
        "type_" / CEnum(
            Int8ub,
            **{t.name: t.value for t in DeviceTypes}
        ),
        "security_level" / Int8ub,
        "flags" / Padded(1, COptional(BitStruct(
            # no per-device flags yet
            Padding(8)
        ))),
        "private_key_len" / Int16ub,
        "private_key" / Bytes(this.private_key_len),
        "client_id_len" / Int16ub,
        "client_id" / Bytes(this.client_id_len)
    )


class Device:
    """
    A minimal implementation of a WVD (Widevine Device) structure,
    modeled after the pywidevine library.

    This class provides a lightweight alternative to the full `pywidevine.Device`,
    retaining only the essential fields for constructing and serializing Widevine device
    blobs in version 2 format, without performing certificate validation or VMP handling.
    """
    Structures = _Structures
    supported_structure = Structures.v2

    def __init__(
            self,
            type_: DeviceTypes,
            security_level: int,
            flags: Optional[dict],
            private_key: RSAPrivateKey,
            client_id: ClientIdentification,
    ):
        """
        Initialize the Device object.

        Args:
            type_ (DeviceTypes or str): The type of device.
            security_level (int): The DRM security level (e.g., 1, 3).
            flags (Optional[dict]): Optional feature flags (reserved for future use).
            private_key (RSAPrivateKey): The device's RSA private key.
            client_id (ClientIdentification): The protobuf client identifier.
        """
        self.type = DeviceTypes[type_] if isinstance(type_, str) else type_
        self.security_level = security_level
        self.flags = flags or {}
        self.private_key = private_key
        self.client_id = client_id

    def dumps(self) -> bytes:
        """
        Serialize the Device object into a WVD-compatible binary format.

        Returns:
            bytes: A binary representation of the device data.
        """
        # Serialize the client ID protobuf message
        bin_client_id = self.client_id.SerializeToString()

        # Serialize the private RSA key to DER format
        bin_private_key = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Build the structured binary representation
        return self.supported_structure.build(dict(
            version=2,
            type_=self.type.value,
            security_level=self.security_level,
            flags=self.flags,
            private_key_len=len(bin_private_key),
            private_key=bin_private_key,
            client_id_len=len(bin_client_id),
            client_id=bin_client_id
        ))


__all__ = ('Device', 'DeviceTypes')
