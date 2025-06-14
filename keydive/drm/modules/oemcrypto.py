from json.encoder import encode_basestring_ascii
from pathlib import Path
from typing import Union, List

from keydive.drm.keybox import KeyBox
from keydive.drm.modules import BaseCdm
from keydive.utils import dumps, b64enc, b64dec


class OEMCrypto(BaseCdm):

    def set_keybox(self, data: bytes) -> None:
        """
        Parses and registers a KeyBox structure used for device provisioning.
        The KeyBox contains cryptographic and device-specific data necessary for DRM.

        Args:
            data (bytes): Raw binary data containing the serialized KeyBox protobuf.
        """
        try:
            # Initialize a new KeyBox instance and parse the protobuf data from bytes
            keybox = KeyBox()
            keybox.ParseFromString(data)  # Parse the raw data into the KeyBox object

            # Check if the stable_id is either not present in the dictionary,
            # or if the existing KeyBox with this stable_id does not have a device_id set.
            if keybox.stable_id not in self._keybox or not self._keybox[keybox.stable_id].device_id:
                # Extract keybox metadata info for logging
                infos = keybox.keybox_info
                # Determine label based on presence of system_id in the keybox info
                label = 'keybox' if infos.get('system_id') else 'encrypted keybox'

                self.logger.info(
                    'Received %s: \n\n%s\n',
                    label, dumps(infos, beauty=True)
                )

                # Store or update the internal keybox dictionary using stable_id as the key
                self._keybox[keybox.stable_id] = keybox
        except Exception as e:
            # Log failure details at debug level to avoid noise in normal logs
            self.logger.debug('Unable to register KeyBox data: %s', e)

    def set_stable_id(self, data: bytes) -> None:
        """
        Registers or updates the stable ID for a KeyBox instance.
        The stable ID uniquely identifies a device and acts as the key
        in the internal KeyBox dictionary.

        Args:
            data (bytes): Stable device identifier as raw bytes,
                          used as the unique key to identify the keybox.

        Notes:
            - If a KeyBox already exists with an empty stable_id, it will be reused;
              otherwise, a new KeyBox instance is created.
        """
        try:
            # Only proceed if this stable ID is not already present in the keybox dictionary
            if data not in self._keybox:
                # Retrieve existing KeyBox with empty stable_id or create a new instance
                keybox = self._keybox.get(b'', KeyBox())

                # Assign the provided stable ID to this KeyBox instance
                keybox.stable_id = data

                # Log the stable ID in a human-readable ASCII-safe format
                self.logger.info(
                    'Received stable ID: \n\n%s\n',
                    encode_basestring_ascii(keybox.stable_id.decode('utf-8')))

                # Store or update the KeyBox in the dictionary with stable_id as the key
                self._keybox[keybox.stable_id] = keybox
        except Exception as e:
            # Log exception details at debug level without interrupting flow
            self.logger.debug('Unable to register KeyBox stable ID: %s', e)

    def set_device_id(self, data: bytes) -> None:
        """
        Registers or updates the device ID within a KeyBox instance.
        The device ID is used to uniquely identify a device for cryptographic
        provisioning and licensing purposes.

        Args:
            data (bytes): Raw device identifier bytes, used to associate a device ID
                          with a KeyBox object.

        Notes:
            - If the device ID is already associated with a KeyBox, this method does nothing.
            - If a KeyBox without a device ID exists, it will be reused; otherwise,
              a new KeyBox instance will be created.
        """
        try:
            # Check if this device ID is already registered in any existing KeyBox
            if not any(k for k in self._keybox.values() if k.device_id == data):
                # Find a KeyBox without a device ID to reuse, or create a new KeyBox
                keybox = next((k for k in self._keybox.values() if not k.device_id), KeyBox())

                # Assign the provided device ID to the KeyBox
                keybox.device_id = data

                # Retrieve device-related metadata for logging purposes
                infos = keybox.device_info
                # Choose label based on whether a system_id is present in metadata
                label = 'device ID' if infos.get('system_id') else 'encrypted device ID'
                self.logger.info(
                    'Received %s: \n\n%s\n',
                    label, dumps(infos, beauty=True) if infos else b64enc(keybox.device_id))

                # Store or update the KeyBox in the dictionary using its stable_id as the key
                self._keybox[keybox.stable_id] = keybox
        except Exception as e:
            # Log exceptions with context at debug level without raising
            self.logger.debug('Unable to register KeyBox device ID: %s', e)

    def set_device_aes_key(self, data: Union[bytes, List[str]]) -> None:
        """
        Imports and stores AES device keys used for decrypting protected content.

        This method accepts either a single AES key as raw bytes or a list of strings
        representing AES keys in various formats, including:
        - Hexadecimal strings
        - Base64-encoded strings (standard or URL-safe)
        - File paths pointing to binary key files

        Args:
            data (bytes or List[str]): The AES key(s) to import. Either a single
                                      16-byte AES key (bytes) or a list of strings
                                      representing keys in different encoded forms or file paths.

        Notes:
            - Only keys exactly 16 bytes in length are accepted as valid AES keys.
            - If a list of strings is given, the method tries each parser (hex, base64, file)
              until one succeeds for each entry.
        """
        if isinstance(data, list):
            # Iterate over all string inputs, attempt parsing with multiple strategies
            for value in data:
                for parser in (bytes.fromhex, b64dec, lambda v: Path(v).read_bytes()):
                    try:
                        # Recursively call with successfully decoded raw bytes
                        self.set_device_aes_key(parser(value))
                        break  # Exit parser loop once successful
                    except Exception:
                        # Ignore failures and try next parser
                        pass
                else:
                    # If no parser succeeded, log the failure with the raw input value
                    self.logger.error('Could not import AES key from input: %s', value)

        # From here on, ensure input is raw bytes representing the AES key
        if not isinstance(data, bytes):
            return

        try:
            # Confirm the AES key length matches 16 bytes (AES-128 standard)
            assert len(data) == 16, f'Invalid AES key length: expected 16 bytes, got {len(data)}'

            # Store the valid AES key into internal cache for later use
            self._device_aes_key.append(data)

            # Log success message with the hex-encoded key for clarity
            self.logger.info('Received device AES key: %s', data.hex())
        except Exception as e:
            # Log any exceptions encountered during key validation or storage
            self.logger.debug('Unable to register device AES key: %s', e)

    def set_encryption_context(self, data: bytes) -> None:
        """
        Registers the encryption context used in content key derivation.

        The encryption context is a blob passed to OEMCrypto or CDM implementations,
        typically including metadata like the label ('ENCRYPTION') and key size.
        It is essential for deriving secure session keys used in content encryption/decryption.

        This function validates and stores the encryption context for use in session key derivation.

        Args:
            data (bytes): A binary blob representing the encryption derivation context.
                          This must begin with a label and end with the encoded key size.

        Notes:
            - Expected structure: b'ENCRYPTION\\x00' + context-specific payload + b'\\x00\\x00\\x00\\x80'
            - The tail 'b"\\x00\\x00\\x00\\x80"' corresponds to 128-bit (0x80) key size in big-endian form.
            - The label is a null-terminated UTF-8 string used in OEMCrypto derivation contexts.
            - Invalid contexts are ignored but logged for debugging.
            """
        try:
            # Constant prefix label used for AES encryption key derivation (null-terminated)
            kEncryptionKeyLabel = b'ENCRYPTION\000'

            # Expected suffix: 128 bits (0x80) in big-endian encoding (for AES-128)
            kEncryptionKeySizeBits = b'\0\0\0\x80'

            # Validate the encryption context starts with the correct label
            assert data.startswith(kEncryptionKeyLabel), 'Context missing expected label: ENCRYPTION\\x00'

            # Validate the encryption context ends with the correct encoded key size
            assert data.endswith(kEncryptionKeySizeBits), 'Context missing expected AES key size specifier'

            # Log that the encryption context was successfully received and registered
            self.logger.info('Received encryption context: %s bytes', len(data))

            # Store the validated encryption context for future use (e.g., key derivation)
            self._context = data
        except Exception as e:
            self.logger.debug('Unable to register encryption context: %s', e)
