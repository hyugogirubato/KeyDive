import base64
import json
import logging

from typing import Literal
from uuid import UUID

from pathlib import Path


def bytes2int(value: bytes, byteorder: Literal['big', 'little'] = 'big', signed: bool = False) -> int:
    """
    Convert bytes to an integer.

    Args:
        value (bytes): The byte sequence to convert.
        byteorder (Literal['big', 'little'], optional): The byte order for conversion. Defaults to 'big'.
        signed (bool, optional): Indicates if the integer is signed. Defaults to False.

    Returns:
        int: The converted integer.
    """
    return int.from_bytes(value, byteorder=byteorder, signed=signed)


class Keybox:
    """
    The Keybox class handles the storage and management of device IDs and keybox data.
    """

    def __init__(self):
        """
        Initializes the Keybox object, setting up a logger and containers for device IDs and keyboxes.

        Attributes:
            logger (Logger): Logger instance for logging messages.
            device_id (list[bytes]): List to store unique device IDs (32 bytes each).
            keybox (dict[bytes, bytes]): Dictionary to map device IDs to their respective keybox data.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        # https://github.com/kaltura/kaltura-device-info-android/blob/master/app/src/main/java/com/kaltura/kalturadeviceinfo/MainActivity.java#L203
        self.device_id = []
        self.keybox = {}

    def set_device_id(self, data: bytes) -> None:
        """
        Set the device ID from the provided data.

        Args:
            data (bytes): The device ID, expected to be 32 bytes long.

        Raises:
            AssertionError: If the data length is not 32 bytes.
        """
        try:
            size = len(data)
            assert size == 32, f'Invalid keybox length: {size}. Should be 32 bytes'

            if data not in self.device_id:
                self.logger.info('Receive device id: \n\n%s\n', base64.b64encode(data).decode('utf-8'))
                self.device_id.append(data)
        except Exception as e:
            self.logger.debug('Failed to set device id: %s', e)

    def set_keybox(self, data: bytes) -> None:
        """
        Set the keybox from the provided data.

        Args:
            data (bytes): The keybox data, expected to be either 128 or 132 bytes long.

        Raises:
            AssertionError: If the data length is not 128 or 132 bytes or does not meet other criteria.
        """
        # https://github.com/wvdumper/dumper/blob/main/Helpers/Keybox.py#L51
        try:
            size = len(data)
            assert size in (128, 132), f'Invalid keybox length: {size}. Should be 128 or 132 bytes'

            if size == 132:
                assert data[128:132] == b"LVL1", 'QSEE style keybox does not end in bytes "LVL1"'

            assert data[120:124] == b"kbox", 'Invalid keybox magic'

            device_id = data[0:32]
            self.set_device_id(data=device_id)

            if device_id not in self.keybox:
                # Fetch keybox info for logging, such as flags and other details
                infos = self.__keybox_info(data)
                self.logger.info('Receive keybox: \n\n%s\n', json.dumps(infos, indent=2))

                # Warn if flags indicate encrypted data, requiring a plain-text device token
                if infos['flags'] > 10:
                    self.logger.warning('Data are encrypted. Device token must be intercepted in plain text')

            self.keybox[device_id] = data
        except Exception as e:
            self.logger.debug('Failed to set keybox: %s', e)

    @staticmethod
    def __keybox_info(data: bytes) -> dict:
        """
        Extract keybox information from the provided data.

        Args:
            data (bytes): The keybox data.

        Returns:
            dict: A dictionary containing extracted keybox information.
        """
        # https://github.com/wvdumper/dumper/blob/main/Helpers/Keybox.py#L51
        # Extract key components from the keybox data based on defined byte offsets.
        content = {
            'device_id': data[0:32],  # Unique identifier for the device (32 bytes).
            'device_key': data[32:48],  # Device-specific cryptographic key (16 bytes).
            'device_token': data[48:120],  # AES key used for device token encryption (72 bytes).
            'keybox_tag': data[120:124].decode('utf-8'),  # Magic tag indicating keybox format (4 bytes).
            'crc32': bytes2int(data[124:128]),  # CRC32 checksum for data integrity verification (4 bytes).
            'level_tag': data[128:132].decode('utf-8') or None,  # Optional tag indicating keybox level (4 bytes).

            # TODO: decrypt device_token field
            # Key components extracted from the device token (Bytes 48–119).
            'flags': bytes2int(data[48:52]),  # Flags indicating various settings (4 bytes).
            'system_id': bytes2int(data[52:56]),  # System identifier for the device (4 bytes).

            # Provisioning ID, encrypted and derived from the unique ID in the system.
            'provisioning_id': UUID(bytes_le=data[56:72]),  # Unique ID for provisioning (16 bytes).

            # Encrypted bits containing device key, key hash, and additional flags.
            'encrypted_bits': data[72:120]  # Encrypted data relevant to the device (48 bytes).
        }

        # Encode certain fields in base64 and convert UUIDs to string
        return {
            k: base64.b64encode(v).decode('utf-8') if isinstance(v, bytes) else str(v) if isinstance(v, UUID) else v
            for k, v in content.items()
        }

    def export(self, parent: Path) -> bool:
        """
        Export the keybox data to a file in the specified parent directory.

        Args:
            parent (Path): The parent directory where the keybox data will be saved.

        Returns:
            bool: True if any keybox were exported, otherwise False.
        """
        keys = self.device_id & self.keybox.keys()
        for k in keys:
            parent.mkdir(parents=True, exist_ok=True)
            path_keybox_bin = parent / 'keybox.bin'
            path_keybox_bin.write_bytes(self.keybox[k])

            self.logger.info('Exported Keybox: %s', path_keybox_bin)
        return len(keys) > 0


__all__ = ('Keybox',)
