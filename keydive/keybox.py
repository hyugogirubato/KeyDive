import base64
import json
import logging

from json.encoder import encode_basestring_ascii
from typing import Literal
from uuid import UUID
from pathlib import Path


def bytes2int(value: bytes, byteorder: Literal["big", "little"] = "big", signed: bool = False) -> int:
    """
    Convert a byte sequence to an integer.

    Parameters:
        value (bytes): The byte sequence to convert.
        byteorder (str, optional): Byte order for conversion. 'big' or 'little'. Defaults to 'big'.
        signed (bool, optional): Whether the integer is signed. Defaults to False.

    Returns:
        int: The integer representation of the byte sequence.
    """
    return int.from_bytes(value, byteorder=byteorder, signed=signed)


class Keybox:
    """
    The Keybox class handles the storage and management of device IDs and keybox data.
    """

    def __init__(self):
        """
        Initializes the Keybox object, setting up logger and containers for device IDs and keyboxes.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        # https://github.com/kaltura/kaltura-device-info-android/blob/master/app/src/main/java/com/kaltura/kalturadeviceinfo/MainActivity.java#L203
        self.device_id = []
        self.keybox = {}

    def set_device_id(self, data: bytes) -> None:
        """
        Set the device ID from the provided data.

        Parameters:
            data (bytes): The device ID, expected to be 32 bytes long.

        Raises:
            AssertionError: If the data length is not 32 bytes.
        """
        try:
            size = len(data)
            # Ensure the device ID is exactly 32 bytes long
            assert size == 32, f"Invalid device ID length: {size}. Should be 32 bytes"

            # Add device ID to the list if it's not already present
            if data not in self.device_id:
                self.logger.info("Receive device id: \n\n%s\n", encode_basestring_ascii(data.decode("utf-8")))
                self.device_id.append(data)

        except Exception as e:
            self.logger.debug("Failed to set device id: %s", e)

    def set_keybox(self, data: bytes) -> None:
        """
        Set the keybox from the provided data.

        Parameters:
            data (bytes): The keybox data, expected to be either 128 or 132 bytes long.

        Raises:
            AssertionError: If the data length is not 128 or 132 bytes or does not meet other criteria.
        """
        # https://github.com/zybpp/Python/tree/master/Python/keybox
        try:
            size = len(data)
            # Validate the keybox size (128 or 132 bytes)
            assert size in (128, 132), f"Invalid keybox length: {size}. Should be 128 or 132 bytes"

            # Validate the QSEE-style keybox end
            assert size == 128 or data[128:132] == b"LVL1", "QSEE-style keybox must end with bytes 'LVL1'"

            # Validate the keybox magic (should be 'kbox')
            assert data[120:124] == b"kbox", "Invalid keybox magic"

            device_id = data[0:32]  # Extract the device ID from the first 32 bytes

            # Retrieve and log the structured keybox information
            infos = self.__keybox_info(data)
            encrypted = infos["flags"] > 10  # Check if the keybox is encrypted
            self.set_device_id(data=device_id)  # Set the device ID

            # Log and store the keybox data if it's a new keybox or the device ID is updated
            if (device_id in self.keybox and self.keybox[device_id] != (data, encrypted)) or device_id not in self.keybox:
                self.logger.info("Receive keybox: \n\n%s\n", json.dumps(infos, indent=2))

                # Warn if keybox is encrypted and interception of plaintext device token is needed
                if encrypted:
                    self.logger.warning("Keybox contains encrypted data. Interception of plaintext device token is needed")

            # Store the keybox (encrypted or not) for the device ID
            if (device_id in self.keybox and not encrypted) or device_id not in self.keybox:
                self.keybox[device_id] = (data, encrypted)
        except Exception as e:
            self.logger.debug("Failed to set keybox: %s", e)

    @staticmethod
    def __keybox_info(data: bytes) -> dict:
        """
        Extract keybox information from the provided data.

        Parameters:
            data (bytes): The keybox data.

        Returns:
            dict: A dictionary containing extracted keybox information.
        """
        # https://github.com/wvdumper/dumper/blob/main/Helpers/Keybox.py#L51

        # Extract device-specific information from the keybox data
        device_token = data[48:120]

        # Prepare the keybox content dictionary
        content = {
            "device_id": data[0:32].decode("utf-8"),  # Device's unique identifier (32 bytes)
            "device_key": data[32:48],  # Device cryptographic key (16 bytes)
            "device_token": device_token,  # Token for device authentication (72 bytes)
            "keybox_tag": data[120:124].decode("utf-8"),  # Magic tag (4 bytes)
            "crc32": bytes2int(data[124:128]),  # CRC32 checksum (4 bytes)
            "level_tag": data[128:132].decode("utf-8") or None,  # Optional level tag (4 bytes)

            # Extract metadata from the device token (Bytes 48–120)
            "flags": bytes2int(device_token[0:4]),  # Device flags (4 bytes)
            "system_id": bytes2int(device_token[4:8]),  # System identifier (4 bytes)
            "provisioning_id": UUID(bytes_le=device_token[8:24]),  # Provisioning UUID (16 bytes)
            "encrypted_bits": device_token[24:72]  # Encrypted device-specific information (48 bytes)
        }

        # https://github.com/ThatNotEasy/Parser-DRM/blob/main/modules/widevine.py#L84
        # TODO: decrypt device token value

        # Encode bytes as base64 and convert UUIDs to string
        return {
            k: base64.b64encode(v).decode("utf-8") if isinstance(v, bytes) else str(v) if isinstance(v, UUID) else v
            for k, v in content.items()
        }

    def export(self, parent: Path) -> bool:
        """
        Export the keybox data to a file in the specified parent directory.

        Parameters:
            parent (Path): The parent directory where the keybox data will be saved.

        Returns:
            bool: True if any keybox were exported, otherwise False.
        """
        # Find matching keyboxes based on the device_id
        keys = self.device_id & self.keybox.keys()

        for k in keys:
            # Create the parent directory if it doesn't exist
            parent.mkdir(parents=True, exist_ok=True)

            # Define the export file path and extension (encrypted or binary)
            path_keybox_bin = parent / ("keybox." + ("enc" if self.keybox[k][1] else "bin"))

            # Write the keybox data to the file
            path_keybox_bin.write_bytes(self.keybox[k][0])

            # Log export status based on whether the keybox is encrypted
            if self.keybox[k][1]:
                self.logger.warning("Exported encrypted keybox: %s", path_keybox_bin)
            else:
                self.logger.info("Exported keybox: %s", path_keybox_bin)

        # Return True if any keyboxes were exported, otherwise False
        return len(keys) > 0


__all__ = ("Keybox",)
