from uuid import UUID

from crccheck.crc import Crc32Mpeg2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.padding import PKCS7

# Convert bytes to a big-endian unsigned integer
bytes2int = lambda x: int.from_bytes(x, byteorder='big', signed=False)


class KeyBox:
    """
    Represents a binary DRM keybox containing a device's unique identifiers and AES key.

    A KeyBox is composed of:
    - A 32-byte stable ID
    - A 16-byte AES key
    - A 72-byte device ID blob (may contain encrypted metadata)
    - A 4-byte 'kbox' tag
    - A 4-byte CRC32 checksum
    - [Optional] A 4-byte 'LVL1' tag (QSEE-specific)

    This class supports both parsing and serialization of this binary format.
    """

    MAGIC_TAG = b'kbox'  # Magic tag required at byte offset 120–124
    LEVEL_TAG = b'LVL1'  # Optional level tag used by QSEE environments (byte offset 128–132)

    def __init__(self):
        self._stable_id = b''  # 32-byte stable device ID
        self._device_aes_key = b''  # 16-byte AES encryption key
        self._device_id = b''  # 72-byte encrypted or encoded device-specific ID blob

    @property
    def stable_id(self) -> bytes:
        """
        Returns the stable ID of the device (32 bytes).

        Returns:
            bytes: The stable device ID.
        """
        return self._stable_id

    @stable_id.setter
    def stable_id(self, value: bytes) -> None:
        """
        Sets the 32-byte stable ID of the device.

        Args:
            value (bytes): A 32-byte stable ID.

        Raises:
            AssertionError: If `value` is not exactly 32 bytes long.
        """
        assert len(value) == 32, f'Invalid stable ID length: expected 32 bytes, got {len(value)}'
        self._stable_id = value

    @property
    def device_aes_key(self) -> bytes:
        """
        Returns the AES encryption key used by the device (16 bytes).

        Returns:
            bytes: The device AES key.
        """
        return self._device_aes_key

    @device_aes_key.setter
    def device_aes_key(self, value: bytes) -> None:
        """
        Sets the 16-byte AES key for the device.

        Args:
            value (bytes): A 16-byte AES key.

        Raises:
            AssertionError: If `value` is not exactly 16 bytes long.
        """
        assert len(value) == 16, f'Invalid AES key length: expected 16 bytes, got {len(value)}'
        self._device_aes_key = value

    @property
    def device_id(self) -> bytes:
        """
        Returns the 72-byte device ID blob.

        Returns:
            bytes: The device-specific identifier blob.
        """
        return self._device_id

    @device_id.setter
    def device_id(self, value: bytes) -> None:
        """
        Sets the device ID blob (72 bytes).

        Args:
            value (bytes): A 72-byte device ID.

        Raises:
            AssertionError: If `value` is not exactly 72 bytes long.
        """
        assert len(value) == 72, f'Invalid device ID length: expected 72 bytes, got {len(value)}'
        self._device_id = value

    def ParseFromString(self, serialized: bytes) -> None:
        """
        Parses and validates a binary keybox structure into its individual fields.

        The expected format is:
        - 32 bytes: stable ID
        - 16 bytes: AES key
        - 72 bytes: device ID
        - 4 bytes: keybox tag (must be "kbox")
        - 4 bytes: CRC32 checksum (MPEG-2 variant)
        - [Optional] 4 bytes: level tag ("LVL1") for QSEE devices

        Args:
            serialized (bytes): Raw keybox data (128 or 132 bytes).

        Raises:
            AssertionError: If data is malformed or fails validation.
        """
        # https://github.com/zybpp/Python/tree/master/Python/keybox
        # Size of the entire serialized keybox (should be either 128 bytes for standard keybox,
        # or 132 bytes for QSEE variant which appends an additional 4-byte level tag)
        size = len(serialized)

        # Validate that the size is either of the two expected formats
        assert size in (128, 132), f'Invalid keybox size: expected 128 or 132 bytes, got {size}'

        # Slice fields from the input
        self.stable_id = serialized[0:32]  # Device's unique identifier (32 bytes)
        self.device_aes_key = serialized[32:48]  # Device cryptographic key (16 bytes)
        self.device_id = serialized[48:120]  # Token for device authentication (72 bytes)

        magic_tag = serialized[120:124]  # Magic tag (4 bytes)
        body_crc = bytes2int(serialized[124:128])  # CRC32 checksum (4 bytes)
        level_tag = serialized[128:132]  # Optional level tag (4 bytes)

        # Ensure the 4-byte magic tag is exactly "kbox"
        assert magic_tag == self.MAGIC_TAG, 'Keybox tag mismatch: expected "kbox"'

        # Validate the checksum using CRC32 MPEG-2 algorithm on the first 124 bytes
        # This ensures data integrity and prevents accidental corruption or tampering
        assert body_crc == Crc32Mpeg2.calc(serialized[:124]), 'CRC32 validation failed'

        # If the optional QSEE tag is present, ensure it exactly matches "LVL1"
        # This tag typically denotes that the keybox is trusted or verified by Qualcomm Secure Execution Environment
        assert size == 128 or level_tag == self.LEVEL_TAG, 'Unexpected QSEE tag: expected "LVL1"'

    @property
    def device_info(self) -> dict:
        """
        Attempts to decode device_id contents into meaningful fields.

        The layout is decoded if the first 4 bytes (flag) are <= 10.
        Otherwise, the format is assumed encrypted or proprietary.

        Returns:
            dict: Decoded fields such as 'flag', 'system_id', 'provisioning_id', and 'encrypted_bits'.
                  Returns an empty dict if layout is unknown.
        """
        # Interpret device_id fields if the flag is within expected range (<= 10)
        flag = bytes2int(self.device_id[0:4])
        if not flag > 10:
            infos = {
                'flag': flag,  # Device flag (4 bytes)
                'system_id': bytes2int(self.device_id[4:8]),  # System identifier (4 bytes)
                'provisioning_id': UUID(bytes_le=self.device_id[8:24]),  # Provisioning UUID (16 bytes)
                'encrypted_bits': self.device_id[24:72]  # Encrypted device-specific information (48 bytes)
            }
        else:
            # Encrypted format or unknown layout; optionally decrypt if format is known
            # https://github.com/ThatNotEasy/Parser-DRM/blob/main/modules/widevine.py#L84
            """
            # Padding to AES block size (16 bytes)
            padder = PKCS7(AES.block_size).padder()
            enc_padded_data = padder.update(self.device_id[0:4]) + padder.finalize()

            # Create AES-ECB cipher with device key
            cipher = Cipher(
                algorithm=AES(self.device_aes_key),
                mode=ECB(),
                backend=default_backend()
            )

            # Decrypt padded data
            decryptor = cipher.decryptor()
            dec_padded_data = decryptor.update(enc_padded_data) + decryptor.finalize()

            # Remove padding to get original data
            unpadder = PKCS7(AES.block_size).unpadder()
            dec_data = unpadder.update(dec_padded_data) + unpadder.finalize()
            """
            infos = {}

        return infos

    @property
    def keybox_info(self) -> dict:
        """
        Extracts all readable keybox metadata for external consumption.

        Returns:
            dict: A dictionary containing raw and interpreted keybox data.
        """
        return {
            'stable_id': self.stable_id,
            'device_aes_key': self.device_aes_key,
            'device_id': self.device_id,
            **self.device_info
        }

    def SerializeToString(self) -> bytes:
        """
        Serializes the current keybox structure to a binary blob.

        Returns:
            bytes: A 128-byte serialized keybox with checksum.

        Raises:
            AssertionError: If any required field is missing.
        """
        # Ensure that all essential components are set; without them, a valid keybox cannot be constructed
        assert self.stable_id and self.device_aes_key and self.device_id, 'Cannot serialize: one or more required fields are missing'

        # This forms the first 124 bytes of the final binary output.
        serialized = self.stable_id + self.device_aes_key + self.device_id + self.MAGIC_TAG

        # Calculate a CRC32 checksum using the MPEG-2 variant on the first 124 bytes
        # This helps verify data integrity when the structure is later read or validated
        body_crc = Crc32Mpeg2.calc(serialized)

        # Convert the CRC integer into a 4-byte big-endian format and append it to the structure
        # This completes the full 128-byte keybox format required by consumers or hardware modules
        return serialized + int.to_bytes(body_crc, length=4, byteorder='big', signed=False)


__all__ = ('KeyBox',)
